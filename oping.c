/**
 * Object oriented C module to send ICMP and ICMPv6 `echo's.
 * Copyright (C) 2006-2017  Florian octo Forster <ff at octo.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; only version 2 of the License is
 * applicable.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "config.h"

#if STDC_HEADERS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#else
#error "You don't have the standard C99 header files installed"
#endif /* STDC_HEADERS */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_MATH_H
#include <math.h>
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#include <arpa/inet.h>

#if HAVE_NETDB_H
#include <netdb.h> /* NI_MAXHOST */
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <locale.h>
#include <langinfo.h>
#include "oping.h"

#ifndef _POSIX_SAVED_IDS
#define _POSIX_SAVED_IDS 0
#endif

#ifndef IPTOS_MINCOST
#define IPTOS_MINCOST 0x02
#endif

/* Remove GNU specific __attribute__ settings when using another compiler */
#if !__GNUC__
#define __attribute__(x) /**/
#endif

typedef struct ping_context
{
    char host[NI_MAXHOST];
    char addr[NI_MAXHOST];
    char device[IFNAMSIZ];
 
    int index;
    int req_sent;
    int req_rcvd;

    double latency_total;
    double tsum2;

#ifndef HISTORY_SIZE_MAX
# define HISTORY_SIZE_MAX 900
#endif
    /* The last n RTTs in the order they were sent. */
    double history_by_time[HISTORY_SIZE_MAX];

    /* Current number of entries in the history. This is a value between 0
     * and HISTORY_SIZE_MAX. */
    size_t history_size;

    /* Total number of reponses received. */
    size_t history_received;

    /* Index of the next RTT to be written to history_by_time. This wraps
     * around to 0 once the histroty has grown to HISTORY_SIZE_MAX. */
    size_t history_index;

    /* The last history_size RTTs sorted by value. timed out packets (NAN
     * entries) are sorted to the back. */
    double history_by_value[HISTORY_SIZE_MAX];

    /* If set to true, history_by_value has to be re-calculated. */
    _Bool history_dirty;
} ping_context_t;

static double  opt_interval   = PING_DEF_TIMEOUT;
static double  opt_timeout    = PING_DEF_TIMEOUT;
static int     opt_addrfamily = PING_DEF_AF;
static char   *opt_srcaddr    = NULL;
static char   *opt_device     = NULL;
static char   *opt_mark       = NULL;
static char   *opt_filename   = NULL;
static int     opt_count      = -1;
static int     opt_send_ttl   = 64;
static uint8_t opt_send_qos   = 0;
#define OPING_DEFAULT_PERCENTILE 95.0
static double  opt_percentile = -1.0;
static double  opt_exit_status_threshold = 1.0;
static char   *opt_outfile    = NULL;
static int     opt_bell       = 0;

static int host_num  = 0;
static FILE *outfile = NULL;

static void sigint_handler (int signal)
{
    /* Make compiler happy */
    signal = 0;
    /* Exit the loop */
    opt_count = 0;
}

static ping_context_t *context_create ()
{
    ping_context_t *ctx = calloc (1, sizeof (*ctx));
    if (ctx == NULL)
        return (NULL);

    return (ctx);
}

static void context_destroy (ping_context_t *context)
{
    if (context == NULL)
        return;

    free (context);
}

static int compare_double (void const *arg0, void const *arg1)
{
    double dbl0 = *((double *) arg0);
    double dbl1 = *((double *) arg1);

    if (isnan (dbl0))
    {
        if (isnan (dbl1))
            return 0;
        else
            return 1;
    }
    else if (isnan (dbl1))
        return -1;
    else if (dbl0 < dbl1)
        return -1;
    else if (dbl0 > dbl1)
        return 1;
    else
        return 0;
}

static void clean_history (ping_context_t *ctx)
{
    size_t i;

    if (!ctx->history_dirty)
        return;

    /* Copy all values from by_time to by_value. */
    memcpy (ctx->history_by_value, ctx->history_by_time,
            sizeof (ctx->history_by_time));

    /* Remove impossible values caused by adding a new host */
    for (i = 0; i < ctx->history_size; i++)
        if (ctx->history_by_value[i] < 0)
            ctx->history_by_value[i] = NAN;

    /* Sort all RTTs. */
    qsort (ctx->history_by_value, ctx->history_size, sizeof
            (ctx->history_by_value[0]), compare_double);

    /* Update the number of received RTTs. */
    ctx->history_received = 0;
    for (i = 0; i < ctx->history_size; i++)
        if (!isnan (ctx->history_by_value[i]))
            ctx->history_received++;

    /* Mark as clean. */
    ctx->history_dirty = 0;
}

static double percentile_to_latency (ping_context_t *ctx,
        double percentile)
{
    size_t index;

    clean_history (ctx);

    /* Not a single packet was received successfully. */
    if (ctx->history_received == 0)
        return NAN;

    if (percentile <= 0.0)
        index = 0;
    else if (percentile >= 100.0)
        index = ctx->history_received - 1;
    else
    {
        index = (size_t) ceil ((percentile / 100.0) * ((double) ctx->history_received));
        assert (index > 0);
        index--;
    }

    return (ctx->history_by_value[index]);
}

static double context_get_packet_loss (const ping_context_t *ctx)
{
    if (ctx == NULL)
        return (-1.0);

    if (ctx->req_sent < 1)
        return (0.0);

    return (100.0 * (ctx->req_sent - ctx->req_rcvd)
            / ((double) ctx->req_sent));
}

static int ping_initialize_contexts (pingobj_t *ping)
{
    pingobj_iter_t *iter;
    int index;
    size_t history_size = 0;

    if (ping == NULL)
        return (EINVAL);

    index = 0;
    for (iter = ping_iterator_get (ping);
            iter != NULL;
            iter = ping_iterator_next (iter))
    {
        ping_context_t *context;
        size_t buffer_size;
        int i;

        context = ping_iterator_get_context(iter);

        /* if this is a previously existing host, do not recreate it */
        if (context != NULL)
        {
            history_size = context->history_size;
            context->index = index++;
            continue;
        }

        context = context_create ();
        context->index = index;

        /* start new hosts at the same graph point as old hosts */
        context->history_size = history_size;
        context->history_index = history_size;
        for (i = 0; i < history_size; i++)
            context->history_by_time[i] = -1;

        buffer_size = sizeof (context->host);
        ping_iterator_get_info (iter, PING_INFO_HOSTNAME, context->host, &buffer_size);

        buffer_size = sizeof (context->addr);
        ping_iterator_get_info (iter, PING_INFO_ADDRESS, context->addr, &buffer_size);

        buffer_size = sizeof (context->device);
        ping_iterator_get_info (iter, PING_INFO_DEVICE, context->device, &buffer_size);

        ping_iterator_set_context (iter, (void *) context);

        index++;
    }

    return (0);
}

static void usage_exit (const char *name, int status)
{
    fprintf (stderr, "Usage: %s [OPTIONS] "
                "-f filename | host [host [host ...]]\n"

            "\nAvailable options:\n"
            "  -4|-6        force the use of IPv4 or IPv6\n"
            "  -c count     number of ICMP packets to send\n"
            "  -i interval  interval with which to send ICMP packets\n"
            "  -w timeout   time to wait for replies, in seconds\n"
            "  -t ttl       time to live for each ICMP packet\n"
            "  -Q qos       Quality of Service (QoS) of outgoing packets\n"
            "               Use \"-Q help\" for a list of valid options.\n"
            "  -I srcaddr   source address\n"
            "  -D device    outgoing interface name\n"
            "  -m mark      mark to set on outgoing packets\n"
            "  -f filename  read hosts from <filename>\n"
            "  -O filename  write RTT measurements to <filename>\n"
            "  -P percent   Report the n'th percentile of latency\n"
            "  -Z percent   Exit with non-zero exit status if more than this percentage of\n"
            "               probes timed out. (default: never)\n"

            "\noping "PACKAGE_VERSION", http://noping.cc/\n"
            "by Florian octo Forster <ff@octo.it>\n"
            "for contributions see `AUTHORS'\n",
            name);
    exit (status);
}

__attribute__((noreturn))
static void usage_qos_exit (const char *arg, int status)
{
    if (arg != 0)
        fprintf (stderr, "Invalid QoS argument: \"%s\"\n\n", arg);

    fprintf (stderr, "Valid QoS arguments (option \"-Q\") are:\n"
            "\n"
            "  Differentiated Services (IPv4 and IPv6, RFC 2474)\n"
            "\n"
            "    be                     Best Effort (BE, default PHB).\n"
            "    ef                     Expedited Forwarding (EF) PHB group (RFC 3246).\n"
            "                           (low delay, low loss, low jitter)\n"
            "    va                     Voice Admit (VA) DSCP (RFC 5865).\n"
            "                           (capacity-admitted traffic)\n"
            "    af[1-4][1-3]           Assured Forwarding (AF) PHB group (RFC 2597).\n"
            "                           For example: \"af12\" (class 1, precedence 2)\n"
            "    cs[0-7]                Class Selector (CS) PHB group (RFC 2474).\n"
            "                           For example: \"cs1\" (priority traffic)\n"
            "\n"
            "  Type of Service (IPv4, RFC 1349, obsolete)\n"
            "\n"
            "    lowdelay     (%#04x)    minimize delay\n"
            "    throughput   (%#04x)    maximize throughput\n"
            "    reliability  (%#04x)    maximize reliability\n"
            "    mincost      (%#04x)    minimize monetary cost\n"
            "\n"
            "  Specify manually\n"
            "\n"
            "    0x00 - 0xff            Hexadecimal numeric specification.\n"
            "       0 -  255            Decimal numeric specification.\n"
            "\n",
            (unsigned int) IPTOS_LOWDELAY,
            (unsigned int) IPTOS_THROUGHPUT,
            (unsigned int) IPTOS_RELIABILITY,
            (unsigned int) IPTOS_MINCOST);

    exit (status);
}

static int set_opt_send_qos (const char *opt)
{
    if (opt == NULL)
        return (EINVAL);

    if (strcasecmp ("help", opt) == 0)
        usage_qos_exit (/* arg = */ NULL, /* status = */ EXIT_SUCCESS);
    /* DiffServ (RFC 2474): */
    /* - Best effort (BE) */
    else if (strcasecmp ("be", opt) == 0)
        opt_send_qos = 0;
    /* - Expedited Forwarding (EF, RFC 3246) */
    else if (strcasecmp ("ef", opt) == 0)
        opt_send_qos = 0xB8; /* == 0x2E << 2 */
    /* - Voice Admit (VA, RFC 5865) */
    else if (strcasecmp ("va", opt) == 0)
        opt_send_qos = 0xB0; /* == 0x2D << 2 */
    /* - Assured Forwarding (AF, RFC 2597) */
    else if ((strncasecmp ("af", opt, strlen ("af")) == 0)
            && (strlen (opt) == 4))
    {
        uint8_t dscp;
        uint8_t class = 0;
        uint8_t prec = 0;

        /* There are four classes, AF1x, AF2x, AF3x, and AF4x. */
        if (opt[2] == '1')
            class = 1;
        else if (opt[2] == '2')
            class = 2;
        else if (opt[2] == '3')
            class = 3;
        else if (opt[2] == '4')
            class = 4;
        else
            usage_qos_exit (/* arg = */ opt, /* status = */ EXIT_SUCCESS);

        /* In each class, there are three precedences, AFx1, AFx2, and AFx3 */
        if (opt[3] == '1')
            prec = 1;
        else if (opt[3] == '2')
            prec = 2;
        else if (opt[3] == '3')
            prec = 3;
        else
            usage_qos_exit (/* arg = */ opt, /* status = */ EXIT_SUCCESS);

        dscp = (8 * class) + (2 * prec);
        /* The lower two bits are used for Explicit Congestion Notification (ECN) */
        opt_send_qos = dscp << 2;
    }
    /* - Class Selector (CS) */
    else if ((strncasecmp ("cs", opt, strlen ("cs")) == 0)
            && (strlen (opt) == 3))
    {
        uint8_t class;

        if ((opt[2] < '0') || (opt[2] > '7'))
            usage_qos_exit (/* arg = */ opt, /* status = */ EXIT_FAILURE);

        /* Not exactly legal by the C standard, but I don't know of any
         * system not supporting this hack. */
        class = ((uint8_t) opt[2]) - ((uint8_t) '0');
        opt_send_qos = class << 5;
    }
    /* Type of Service (RFC 1349) */
    else if (strcasecmp ("lowdelay", opt) == 0)
        opt_send_qos = IPTOS_LOWDELAY;
    else if (strcasecmp ("throughput", opt) == 0)
        opt_send_qos = IPTOS_THROUGHPUT;
    else if (strcasecmp ("reliability", opt) == 0)
        opt_send_qos = IPTOS_RELIABILITY;
    else if (strcasecmp ("mincost", opt) == 0)
        opt_send_qos = IPTOS_MINCOST;
    /* Numeric value */
    else
    {
        unsigned long value;
        char *endptr;

        errno = 0;
        endptr = NULL;
        value = strtoul (opt, &endptr, /* base = */ 0);
        if ((errno != 0) || (endptr == opt)
                || (endptr == NULL) || (*endptr != 0)
                || (value > 0xff))
            usage_qos_exit (/* arg = */ opt, /* status = */ EXIT_FAILURE);
        
        opt_send_qos = (uint8_t) value;
    }

    return (0);
}

static char *format_qos (uint8_t qos, char *buffer, size_t buffer_size)
{
    uint8_t dscp;
    uint8_t ecn;
    char *dscp_str;
    char *ecn_str;

    dscp = qos >> 2;
    ecn = qos & 0x03;

    switch (dscp)
    {
        case 0x00: dscp_str = "be";  break;
        case 0x2e: dscp_str = "ef";  break;
        case 0x2d: dscp_str = "va";  break;
        case 0x0a: dscp_str = "af11"; break;
        case 0x0c: dscp_str = "af12"; break;
        case 0x0e: dscp_str = "af13"; break;
        case 0x12: dscp_str = "af21"; break;
        case 0x14: dscp_str = "af22"; break;
        case 0x16: dscp_str = "af23"; break;
        case 0x1a: dscp_str = "af31"; break;
        case 0x1c: dscp_str = "af32"; break;
        case 0x1e: dscp_str = "af33"; break;
        case 0x22: dscp_str = "af41"; break;
        case 0x24: dscp_str = "af42"; break;
        case 0x26: dscp_str = "af43"; break;
        case 0x08: dscp_str = "cs1";  break;
        case 0x10: dscp_str = "cs2";  break;
        case 0x18: dscp_str = "cs3";  break;
        case 0x20: dscp_str = "cs4";  break;
        case 0x28: dscp_str = "cs5";  break;
        case 0x30: dscp_str = "cs6";  break;
        case 0x38: dscp_str = "cs7";  break;
        default:   dscp_str = NULL;
    }

    switch (ecn)
    {
        case 0x01: ecn_str = ",ecn(1)"; break;
        case 0x02: ecn_str = ",ecn(0)"; break;
        case 0x03: ecn_str = ",ce"; break;
        default:   ecn_str = "";
    }

    if (dscp_str == NULL)
        snprintf (buffer, buffer_size, "0x%02x%s", dscp, ecn_str);
    else
        snprintf (buffer, buffer_size, "%s%s", dscp_str, ecn_str);
    buffer[buffer_size - 1] = 0;

    return (buffer);
}

static int read_options (int argc, char **argv)
{
    int optchar;

    while (1)
    {
        optchar = getopt (argc, argv, "46c:hi:I:t:Q:f:D:Z:O:P:m:w:b");

        if (optchar == -1)
            break;

        switch (optchar)
        {
            case '4':
            case '6':
                opt_addrfamily = (optchar == '4') ? AF_INET : AF_INET6;
                break;

            case 'c':
                {
                    int new_count;
                    new_count = atoi (optarg);
                    if (new_count > 0)
                    {
                        opt_count = new_count;

                        if ((opt_percentile < 0.0) && (opt_count < 20))
                            opt_percentile = 100.0 * (opt_count - 1) / opt_count;
                    }
                    else
                        fprintf(stderr, "Ignoring invalid count: %s\n",
                                optarg);
                }
                break;

            case 'f':
                {
                    if (opt_filename != NULL)
                        free (opt_filename);
                    opt_filename = strdup (optarg);
                }
                break;

            case 'i':
                {
                    double new_interval;
                    new_interval = atof (optarg);
                    if (new_interval < 0.001)
                        fprintf (stderr, "Ignoring invalid interval: %s\n",
                                optarg);
                    else
                        opt_interval = new_interval;
                }
                break;

            case 'w':
                {
                    char *endp = NULL;
                    double t = strtod (optarg, &endp);
                    if ((optarg[0] != 0) && (endp != NULL) && (*endp == 0))
                        opt_timeout = t;
                    else
                        fprintf (stderr, "Ignoring invalid timeout: %s\n",
                                optarg);
                }
                break;

            case 'I':
                {
                    if (opt_srcaddr != NULL)
                        free (opt_srcaddr);
                    opt_srcaddr = strdup (optarg);
                }
                break;

            case 'D':
                opt_device = optarg;
                break;

            case 'm':
                opt_mark = optarg;
                break;

            case 't':
            {
                int new_send_ttl;
                new_send_ttl = atoi (optarg);
                if ((new_send_ttl > 0) && (new_send_ttl < 256))
                    opt_send_ttl = new_send_ttl;
                else
                    fprintf (stderr, "Ignoring invalid TTL argument: %s\n",
                            optarg);
                break;
            }

            case 'Q':
                set_opt_send_qos (optarg);
                break;

            case 'O':
                {
                    free (opt_outfile);
                    opt_outfile = strdup (optarg);
                }
                break;

            case 'P':
                {
                    double new_percentile;
                    new_percentile = atof (optarg);
                    if (isnan (new_percentile)
                            || (new_percentile < 0.1)
                            || (new_percentile > 100.0))
                        fprintf (stderr, "Ignoring invalid percentile: %s\n",
                                optarg);
                    else
                        opt_percentile = new_percentile;
                }
                break;
            case 'b':
                opt_bell = 1;
                break;

            case 'Z':
            {
                char *endptr = NULL;
                double tmp;

                errno = 0;
                tmp = strtod (optarg, &endptr);
                if ((errno != 0) || (endptr == NULL) || (*endptr != 0) || (tmp < 0.0) || (tmp > 100.0))
                {
                    fprintf (stderr, "Ignoring invalid -Z argument: %s\n", optarg);
                    fprintf (stderr, "The \"-Z\" option requires a numeric argument between 0 and 100.\n");
                }
                else
                    opt_exit_status_threshold = tmp / 100.0;

                break;
            }

            case 'h':
                usage_exit (argv[0], 0);
                break;

            default:
                usage_exit (argv[0], 1);
        }
    }

    if (opt_percentile <= 0.0)
        opt_percentile = OPING_DEFAULT_PERCENTILE;

    return (optind);
}

static void time_normalize (struct timespec *ts)
{
    while (ts->tv_nsec < 0)
    {
        if (ts->tv_sec == 0)
        {
            ts->tv_nsec = 0;
            return;
        }

        ts->tv_sec  -= 1;
        ts->tv_nsec += 1000000000;
    }

    while (ts->tv_nsec >= 1000000000)
    {
        ts->tv_sec  += 1;
        ts->tv_nsec -= 1000000000;
    }
}

static void time_calc (struct timespec *ts_dest,
        const struct timespec *ts_int,
        const struct timeval  *tv_begin,
        const struct timeval  *tv_end)
{
    ts_dest->tv_sec = tv_begin->tv_sec + ts_int->tv_sec;
    ts_dest->tv_nsec = (tv_begin->tv_usec * 1000) + ts_int->tv_nsec;
    time_normalize (ts_dest);

    /* Assure that `(begin + interval) > end'.
     * This may seem overly complicated, but `tv_sec' is of type `time_t'
     * which may be `unsigned. *sigh* */
    if ((tv_end->tv_sec > ts_dest->tv_sec)
            || ((tv_end->tv_sec == ts_dest->tv_sec)
                && ((tv_end->tv_usec * 1000) > ts_dest->tv_nsec)))
    {
        ts_dest->tv_sec  = 0;
        ts_dest->tv_nsec = 0;
        return;
    }

    ts_dest->tv_sec = ts_dest->tv_sec - tv_end->tv_sec;
    ts_dest->tv_nsec = ts_dest->tv_nsec - (tv_end->tv_usec * 1000);
    time_normalize (ts_dest);
}

int timeval_cmp(struct timeval *tv1, struct timeval *tv2)
{
    if (tv1->tv_sec > tv2->tv_sec)
        return 1;
    if (tv1->tv_sec < tv2->tv_sec)
        return -1;
    if (tv1->tv_usec > tv2->tv_usec)
        return 1;
    if (tv1->tv_usec < tv2->tv_usec)
        return -1;
    return 0;
}

static int pre_loop_hook (pingobj_t *ping) /* {{{ */
{
    pingobj_iter_t *iter;

    for (iter = ping_iterator_get (ping);
            iter != NULL;
            iter = ping_iterator_next (iter))
    {
        ping_context_t *ctx;
        size_t buffer_size;

        ctx = ping_iterator_get_context (iter);
        if (ctx == NULL)
            continue;

        buffer_size = 0;
        ping_iterator_get_info (iter, PING_INFO_DATA, NULL, &buffer_size);

        printf ("PING %s (%s) %zu bytes of data. dev %s\n",
                ctx->host, ctx->addr, buffer_size, ctx->device);
    }

    return (0);
}

static int pre_sleep_hook (__attribute__((unused)) pingobj_t *ping) /* {{{ */
{
    fflush (stdout);

    return (0);
}

static int post_sleep_hook (__attribute__((unused)) pingobj_t *ping) /* {{{ */
{
    return (0);
}

static void update_context (ping_context_t *ctx, double latency) /* {{{ */
{
    ctx->req_sent++;

    if (latency > 0.0)
    {
        ctx->req_rcvd++;
        ctx->latency_total += latency;
        ctx->tsum2 += latency * latency;
    }
    else
    {
        latency = NAN;
    }

    ctx->history_by_time[ctx->history_index] = latency;

    ctx->history_dirty = 1;

    /* Update index and size. */
    ctx->history_index = (ctx->history_index + 1) % HISTORY_SIZE_MAX;
    if (ctx->history_size < HISTORY_SIZE_MAX)
        ctx->history_size++;
}

static int update_host_hook (pingobj_iter_t *iter, /* {{{ */
        __attribute__((unused)) int index, struct timeval *tv_now,
        struct timeval *tv_out)
{
    double          latency;
    unsigned long   sequence;
    int             recv_ttl;
    uint8_t         recv_qos;
    char            recv_qos_str[16];
    struct timeval  tv_send;
    struct timeval  tv_end;
    size_t          buffer_len;
    size_t          data_len;
    ping_context_t *context;


    timerclear(&tv_send);
    buffer_len = sizeof(struct timeval);
    ping_iterator_get_info (iter, PING_INFO_TIME,
             &tv_send, &buffer_len);
    if (!timerisset(&tv_send))
    {
        return 0;
    }
    timeradd(&tv_send, tv_out, &tv_end);
    if (tv_end.tv_sec > tv_now->tv_sec || 
        (tv_end.tv_sec == tv_now->tv_sec && tv_end.tv_usec > tv_now->tv_usec))
    {
        return 0;
    }

    latency = -1.0;
    buffer_len = sizeof (latency);
    ping_iterator_get_info (iter, PING_INFO_LATENCY,
            &latency, &buffer_len);

    sequence = 0;
    buffer_len = sizeof (sequence);
    ping_iterator_get_info (iter, PING_INFO_SEQUENCE,
            &sequence, &buffer_len);

    recv_ttl = -1;
    buffer_len = sizeof (recv_ttl);
    ping_iterator_get_info (iter, PING_INFO_RECV_TTL,
            &recv_ttl, &buffer_len);

    recv_qos = 0;
    buffer_len = sizeof (recv_qos);
    ping_iterator_get_info (iter, PING_INFO_RECV_QOS,
            &recv_qos, &buffer_len);

    data_len = 0;
    ping_iterator_get_info (iter, PING_INFO_DATA,
            NULL, &data_len);

    context = (ping_context_t *) ping_iterator_get_context (iter);

#define HOST_PRINTF(...) printf(__VA_ARGS__)

    update_context (context, latency);

    if (latency > 0.0)
    {
        HOST_PRINTF ("%zu bytes from %s (%s): icmp_seq=%lu ttl=%i ",
                data_len,
                context->host, context->addr,
                sequence, recv_ttl);
        if ((recv_qos != 0) || (opt_send_qos != 0))
        {
            HOST_PRINTF ("qos=%s ",
                    format_qos (recv_qos, recv_qos_str, sizeof (recv_qos_str)));
        }
        HOST_PRINTF ("time=%.2f ms\n", latency);

        if (opt_bell) {
            HOST_PRINTF ("\a");
        }
    }
    else /* if (!(latency > 0.0)) */
    {
        HOST_PRINTF ("echo reply from %s (%s): icmp_seq=%lu timeout\n",
                context->host, context->addr,
                sequence);
    }

    if (outfile != NULL)
    {
        struct timeval tv = {0};
        if (gettimeofday (&tv, NULL) == 0)
        {
            double t = ((double) tv.tv_sec) + (((double) tv.tv_usec) / 1000000.0);

            if ((sequence % 32) == 0)
                fprintf (outfile, "#time,host,latency[ms]\n");

            fprintf (outfile, "%.3f,\"%s\",%.2f\n", t, context->host, latency);
        }
    }

    ping_iterator_inc_index(iter);

    return 1;
}

/* Prints statistics for each host, cleans up the contexts and returns the
 * number of hosts which failed to return more than the fraction
 * opt_exit_status_threshold of pings. */
static int post_loop_hook (pingobj_t *ping)
{
    pingobj_iter_t *iter;
    int failure_count = 0;

    for (iter = ping_iterator_get (ping);
            iter != NULL;
            iter = ping_iterator_next (iter))
    {
        ping_context_t *context;

        context = ping_iterator_get_context (iter);

        printf ("\n--- %s ping statistics ---\n"
                "%i packets transmitted, %i received, %.2f%% packet loss, time %.1fms\n",
                context->host, context->req_sent, context->req_rcvd,
                context_get_packet_loss (context),
                context->latency_total);

        {
            double pct_failed = 1.0 - (((double) context->req_rcvd)
                    / ((double) context->req_sent));
            if (pct_failed > opt_exit_status_threshold)
                failure_count++;
        }

        if (context->req_rcvd != 0)
        {
            double min;
            double median;
            double max;
            double percentile;
            double mdev;

            min = percentile_to_latency (context, 0.0);
            median = percentile_to_latency (context, 50.0);
            max = percentile_to_latency (context, 100.0);
            percentile = percentile_to_latency (context, opt_percentile);
            mdev = sqrt(context->tsum2 / context->req_rcvd - 
                (context->latency_total / context->req_rcvd) *
                (context->latency_total / context->req_rcvd));

            printf ("RTT[ms]: min = %.0f, median = %.0f, p(%.0f) = %.0f, max = %.0f mdev = %.0f\n",
                    min, median, opt_percentile, percentile, max, mdev);
        }

        ping_iterator_set_context (iter, NULL);
        context_destroy (context);
    }

    return (failure_count);
}

int main (int argc, char **argv)
{
    pingobj_t      *ping;
    pingobj_iter_t *iter;
    struct sigaction sigint_action;
    struct timeval  tv_begin;
    struct timeval  tv_end;
    struct timeval  tv_interval;
    struct timeval  tv_out;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr *addr;
    socklen_t addr_len;
    int optind;
    int i;
    int status;

    setlocale(LC_ALL, "");
    optind = read_options (argc, argv);

    if ((optind >= argc) && (opt_filename == NULL)) {
        usage_exit (argv[0], 1);
    }

    if ((ping = ping_construct ()) == NULL)
    {
        fprintf (stderr, "ping_construct failed\n");
        return (1);
    }

    if (ping_setopt (ping, PING_OPT_TTL, &opt_send_ttl) != 0)
    {
        fprintf (stderr, "Setting TTL to %i failed: %s\n",
                opt_send_ttl, ping_get_error (ping));
    }

    if (ping_setopt (ping, PING_OPT_QOS, &opt_send_qos) != 0)
    {
        fprintf (stderr, "Setting TOS to %i failed: %s\n",
                opt_send_qos, ping_get_error (ping));
    }

    {
        double temp_sec;
        double temp_usec;

        temp_usec = modf (opt_interval, &temp_sec);
        tv_interval.tv_sec  = (time_t) temp_sec;
        tv_interval.tv_usec = (long) (temp_usec * 1000000L);

        /* printf ("ts_int = %i.%09li\n", (int) ts_int.tv_sec, ts_int.tv_nsec); */
    }

    if (ping_setopt (ping, PING_OPT_TIMEOUT, (void*)(&opt_timeout)) != 0)
    {
        fprintf (stderr, "Setting timeout failed: %s\n",
                ping_get_error (ping));
    }

    if (ping_setopt (ping, PING_OPT_INTERVAL, (void*)(&opt_interval)) != 0)
    {
        fprintf (stderr, "Setting timeout failed: %s\n",
                ping_get_error (ping));
    }

    if (opt_addrfamily != PING_DEF_AF)
        ping_setopt (ping, PING_OPT_AF, (void *) &opt_addrfamily);

    if (opt_srcaddr != NULL)
    {
        if (ping_setopt (ping, PING_OPT_SOURCE, (void *) opt_srcaddr) != 0)
        {
            fprintf (stderr, "Setting source address failed: %s\n",
                    ping_get_error (ping));
        }
    }

    if (opt_device != NULL)
    {
        if (ping_setopt (ping, PING_OPT_DEVICE, (void *) opt_device) != 0)
        {
            fprintf (stderr, "Setting device failed: %s\n",
                    ping_get_error (ping));
        }
    }

    if (opt_mark != NULL)
    {
        char *endp = NULL;
        int mark = (int) strtol (opt_mark, &endp, /* base = */ 0);
        if ((opt_mark[0] != 0) && (endp != NULL) && (*endp == 0))
        {
            if (ping_setopt(ping, PING_OPT_MARK, (void*)(&mark)) != 0)
            {
                fprintf (stderr, "Setting mark failed: %s\n",
                    ping_get_error (ping));
            }
        }
        else
        {
            fprintf(stderr, "Ignoring invalid mark: %s\n", optarg);
        }
    }

    if (opt_filename != NULL)
    {
        FILE *infile;
        char line[256];
        char host[256];
        char srcaddr[256];
        char device[256];

        if (strcmp (opt_filename, "-") == 0)
            /* Open STDIN */
            infile = fdopen(0, "r");
        else
            infile = fopen(opt_filename, "r");

        if (infile == NULL)
        {
            fprintf (stderr, "Opening %s failed: %s\n",
                    (strcmp (opt_filename, "-") == 0)
                    ? "STDIN" : opt_filename,
                    strerror(errno));
            return (1);
        }

        while (fgets(line, sizeof(line), infile))
        {
            memset(host, 0, sizeof(host));
            memset(srcaddr, 0, sizeof(srcaddr));
            memset(device, 0, sizeof(device));
            memset(&addr4, 0, sizeof(addr4));
            memset(&addr6, 0, sizeof(addr6));
            addr4.sin_family = AF_INET;
            addr6.sin6_family = AF_INET6;

            /* Strip whitespace */
            if (sscanf(line, "%s %s %s", host, srcaddr, device) < 1)
                continue;

            if ((host[0] == 0) || (host[0] == '#'))
                continue;

            if (srcaddr[0] == 0)
            {
                addr = NULL;
                addr_len = 0;
            }
            else
            {
                if (inet_pton(AF_INET, srcaddr, &addr4.sin_addr))
                {
                    addr = (struct sockaddr *)&addr4;
                }
                else if(inet_pton(AF_INET6, srcaddr, &addr6.sin6_addr))
                {
                    addr = (struct sockaddr *)&addr6;
                }
                else
                {
                    continue;
                }
            }

            if (strlen(device) && strlen(device) >= IFNAMSIZ)
                continue;

            if (ping_host_add(ping, host, addr, sizeof(*addr), device) < 0)
            {
                const char *errmsg = ping_get_error (ping);

                fprintf (stderr, "Adding host `%s' failed: %s\n", host, errmsg);
                continue;
            }
            else
            {
                host_num++;
            }
        }

        fclose(infile);
    }

    for (i = optind; i < argc; i++)
    {
        if (ping_host_add (ping, argv[i], NULL, 0, NULL) < 0)
        {
            const char *errmsg = ping_get_error (ping);

            fprintf (stderr, "Adding host `%s' failed: %s\n", argv[i], errmsg);
            continue;
        }
        else
        {
            host_num++;
        }
    }

    if (host_num == 0)
        exit (EXIT_FAILURE);

    if (opt_outfile != NULL)
    {
        outfile = fopen (opt_outfile, "a");
        if (outfile == NULL)
        {
            fprintf (stderr, "opening \"%s\" failed: %s\n",
                 opt_outfile, strerror (errno));
            exit (EXIT_FAILURE);
        }
    }

    ping_initialize_contexts (ping);

    if (i == 0)
        return (1);

    memset (&sigint_action, '\0', sizeof (sigint_action));
    sigint_action.sa_handler = sigint_handler;
    if (sigaction (SIGINT, &sigint_action, NULL) < 0)
    {
        perror ("sigaction");
        return (1);
    }

    /* Set up timeout */
    tv_out.tv_sec = (time_t) opt_timeout;
    tv_out.tv_usec = (suseconds_t) (1000000 * (opt_timeout - ((double) tv_out.tv_sec)));

    pre_loop_hook (ping);

    while (opt_count != 0)
    {
        int index;
        int status;

        if (gettimeofday (&tv_begin, NULL) < 0)
        {
            perror ("gettimeofday");
            return (1);
        }

        status = ping_send (ping);
        if (status == -EINTR)
        {
            continue;
        }
        else if (status < 0)
        {
            fprintf (stderr, "ping_send failed: %s\n",
                    ping_get_error (ping));
            return (1);
        }

        timeradd(&tv_begin, &tv_interval, &tv_end);
        ping_recv(ping, &tv_end);

        if (gettimeofday (&tv_end, NULL) < 0)
        {
            perror ("gettimeofday");
            return (1);
        }

        index = 0;
        for (iter = ping_iterator_get (ping);
                iter != NULL;
                iter = ping_iterator_next (iter))
        {
            while (update_host_hook (iter, index, &tv_end, &tv_out));
            index++;
        }

        struct timeval tv_out_bak = tv_out;;
        while (opt_count == 1 && timeval_cmp(&tv_out, &tv_interval) > 0)
        {
            timeradd(&tv_end, &tv_interval, &tv_end);
            ping_recv(ping, &tv_end);
            if (gettimeofday (&tv_end, NULL) < 0)
            {
                perror ("gettimeofday");
                return (1);
            }

            index = 0;
            for (iter = ping_iterator_get (ping);
                    iter != NULL;
                    iter = ping_iterator_next (iter))
            {
                while (update_host_hook (iter, index, &tv_end, &tv_out_bak));
                index++;
            }
            timersub(&tv_out, &tv_interval, &tv_out);
        }

        pre_sleep_hook (ping);

        post_sleep_hook (ping);

        if (opt_count > 0)
            opt_count--;
    } /* while (opt_count != 0) */

    /* Returns the number of failed hosts according to -Z. */
    status = post_loop_hook (ping);

    ping_destroy (ping);

    if (outfile != NULL)
    {
        fclose (outfile);
        outfile = NULL;
    }

    if (status == 0)
        exit (EXIT_SUCCESS);
    else
    {
        if (status > 255)
            status = 255;
        exit (status);
    }
}

