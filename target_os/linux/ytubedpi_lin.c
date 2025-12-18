#include "ytubedpi_lin.h"
#include <stdio.h>
#include <signal.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>


/**
 * Worker stop flag.
 */
static volatile sig_atomic_t loop_stop = 0;


static void _yt__sig_handler(int n)
{
    (void)n;

    /** already stopped (double signal failure pervention) */
    if (loop_stop)
    {
        return;
    }

    /**
     * Stop worker.
     */
    loop_stop = 1;
}

/**
 * Packet processing point.
 */
static int _yt__cb(struct nfq_q_handle* qhandle, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
    struct nfqnl_msg_packet_hdr* ph;
    u_int32_t id; /** NFQUEUE packet ID */
    unsigned char* pkt;
    struct iphdr* hdr_ip;
    struct tcphdr* hdr_tcp;
    int len_recv, len_send;
    struct sockaddr_in sin = { .sin_family = AF_INET, .sin_port = 0, .sin_addr = { 0 } };

    (void)nfmsg;
    (void)data;

    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    len_recv = nfq_get_payload(nfa, &pkt);
    if (len_recv < 0)
    {
        printf("nfq_get_payload() error\n");
        return nfq_set_verdict(qhandle, id, NF_ACCEPT, 0, NULL);
    }

    /**
     * Packet processing.
     */
    hdr_ip = (struct iphdr*)pkt;
    if (hdr_ip->version != 4)
    {
        return nfq_set_verdict(qhandle, id, NF_ACCEPT, 0, NULL);
    }

    hdr_tcp = (struct tcphdr*)&(pkt[hdr_ip->ihl * 4]);

    if (hdr_ip->protocol == 0x06 /** TCP */
        && 1
        )
    {

        /** Send */
        goto send_modified;
    }


    /**
     * Send modified packet (then drop original).
     */
send_modified:
    printf("len= %d, daddr= 0x%08X\n", len_send, sin.sin_addr.s_addr);


    if (sendto(ctx->sock_tx, pkt1, len_send, 0, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0)
    {
        printf("Sendto failed! Length %d. Drop\n", len_send);
        dump(len_send, pkt1);
    }

    /**
     * Drop original packet.
     */
drop:
    return nfq_set_verdict(qhandle, id, NF_DROP, 0, NULL);

    /**
     * Send original packet.
     */
send_original:
    return nfq_set_verdict(qhandle, id, NF_ACCEPT, 0, NULL);
}


/**
 * Main recv loop.
 */
static void* _yt__worker_main(void* data)
{
    int		rv;
    char	buf[YT_MAX_PACKET_SIZE] __attribute__((aligned));
    (void)data;

    w2e_log_printf("worker start\n");

    while (!loop_stop)
    {
        rv = recv(ctx->fd, buf, sizeof(buf), 0);
        if (rv >= 0)
        {
            nfq_handle_packet(ctx->h, buf, rv);
        }
        else
        {
            w2e_error_printf("recv() error (errno= %d)\n", errno);
        }
    }

    w2e_log_printf("worker exit (NFQUEUE id %d)\n", ctx->id);
    return NULL;
}

/**
 * Init NFQUEUE and its context.
 */
static int __w2e_server__nfqueue_init(w2e_nfqueue_ctx* ctx, int id)
{
    w2e_log_printf("Opening library handle\n");
    ctx->h = nfq_open();
    if (!ctx->h)
    {
        w2e_error_printf("Error during nfq_open()\n");
        return 1;
    }

    w2e_log_printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(ctx->h, AF_INET) < 0)
    {
        w2e_error_printf("Error during nfq_unbind_pf()\n");
        return 1;
    }

    w2e_log_printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(ctx->h, AF_INET) < 0)
    {
        w2e_error_printf("Error during nfq_bind_pf()\n");
        return 1;
    }

    ctx->id = id;
    w2e_log_printf("Binding to queue %d (total %d)\n", ctx->id, W2E_SERVER_NFQUEUE_NUM);
    ctx->qh = nfq_create_queue(ctx->h, ctx->id, &__w2e_server__cb, ctx);
    if (!ctx->qh)
    {
        w2e_error_printf("Error during nfq_create_queue()\n");
        return 1;
    }

    w2e_log_printf("Setting copy_packet mode\n");
    if (nfq_set_mode(ctx->qh, NFQNL_COPY_PACKET, W2E_MAX_PACKET_SIZE) < 0)
    {
        w2e_error_printf("Can't set packet_copy mode\n");
        return 1;
    }

    w2e_log_printf("Setting queue length to %d\n", W2E_SERVER_QUEUE_BUFSIZ / W2E_MAX_PACKET_SIZE);
    if (nfq_set_queue_maxlen(ctx->qh, W2E_SERVER_QUEUE_BUFSIZ / W2E_MAX_PACKET_SIZE) < 0)
    {
        w2e_error_printf("Can't set packet_copy mode\n");
        return 1;
    }

    ctx->fd = nfq_fd(ctx->h);
    return 0;
}

/**
 * NFQUEUE deinit.
 */
static void __w2e_server__nfqueue_deinit(w2e_nfqueue_ctx* ctx)
{
    nfq_destroy_queue(ctx->qh);
    nfq_close(ctx->h);
}
static int __w2e_server__iptables_add(
    const char* iface,		/** interface name */
    const char* proto,		/** protocol name */
    const char* port_dir,	/** port direction src or dst: {"--sport", "--dport"} */
    const char* port,		/** port value/range */
    const char* balance		/** balance queues: must be "0:x", where x= W2E_SERVER_NFQUEUE_NUM-1, or "0" if W2E_SERVER_NFQUEUE_NUM==1 */
)
{
    int stat;
    char* const args[] = {
        "iptables", "-t", "raw", "-A", "PREROUTING",
        "-p", proto, port_dir, port, "-i", iface,
        "-j", "NFQUEUE", "--queue-bypass",
#if W2E_SERVER_NFQUEUE_NUM > 1
        "--queue-balance",
#else // W2E_SERVER_NFQUEUE_NUM <= 1
        "--queue-num",
#endif // W2E_SERVER_NFQUEUE_NUM <= 1
        balance, NULL };

    int pid = fork();

    if (pid == -1)
    {
        w2e_error_printf("fork error\n");
        return 1;
    }
    else if (pid == 0)
    {
        execvp("iptables", args);
        w2e_error_printf("exec error\n"); /** exec never returns */
        exit(1);
    }

    waitpid(pid, &stat, 0);
    w2e_dbg_printf("return %d\n", stat);
    return stat;
}


int main(int argc, char* argv[])
{
    printf("test\n");


    /**
     * Create raw sockets.
     */
    for (int i = 0; i < W2E_SERVER_NFQUEUE_NUM; i++)
    {
        /** Socket */
        nfqueue_ctx[i].sock_tx = __w2e_server__sock_init();
        if (nfqueue_ctx[i].sock_tx == -1)
        {
            w2e_error_printf("Error create socket %d\n", i);

            for (int j = 0; j < i; j++)
            {
                close(nfqueue_ctx[j].sock_tx);
            }
            ret = 1;
            goto exit_crypto_deinit;
        }
    }

    /** Create NFQUEUEs */
    for (int i = 0; i < W2E_SERVER_NFQUEUE_NUM; i++)
    {
        if (__w2e_server__nfqueue_init(&(nfqueue_ctx[i]), i) != 0)
        {
            w2e_error_printf("Error create NFQUEUE %d\n", i);

            for (int j = 0; j < i; j++)
            {
                __w2e_server__nfqueue_deinit(&(nfqueue_ctx[j]));
            }
            ret = 1;
            goto exit_close_sockets;
        }
    }


    /****************************************************************
     * OPERATION START.
     ***************************************************************/

    w2e_log_printf("Operation START\n");

    /**
     * Start workers.
     */
    for (int i = 0; i < W2E_SERVER_NFQUEUE_NUM; i++)
    {
        pthread_create(&(nfqueue_workers[i]), NULL, __w2e_server__worker_main, &(nfqueue_ctx[i]));
    }

    /**
     * Wait for workers.
     */
    for (int i = 0; i < W2E_SERVER_NFQUEUE_NUM; i++)
    {
        pthread_join(nfqueue_workers[i], NULL);
    }


    /****************************************************************
     * DEINITIALIZATION.
     ***************************************************************/

     /*exit_nfqueue_deinit:*/
    w2e_log_printf("Deinitialize NFQUEUES\n");
    for (int i = 0; i < W2E_SERVER_NFQUEUE_NUM; i++)
    {
        __w2e_server__nfqueue_deinit(&(nfqueue_ctx[i]));
    }

exit_close_sockets:
    w2e_log_printf("Deinitialize sockets\n");
    for (int i = 0; i < W2E_SERVER_NFQUEUE_NUM; i++)
    {
        close(nfqueue_ctx[i].sock_tx);
    }

    return 0;
}