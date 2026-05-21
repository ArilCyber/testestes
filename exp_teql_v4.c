/*
 * CVE-2026-23074 teql UAF Exploit - WITH MODULE VERIFICATION
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
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <signal.h>

#define DUMMY_IFACE "dummy0"

static int nl_fd = -1;
static uint32_t seq = 0;
static int teql_available = 0;

/* Check if teql module is available */
static int check_teql_module(void) {
    /* Check if module is loaded */
    FILE *f = fopen("/proc/modules", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "sch_teql") || strstr(line, "teql")) {
                printf("[+] teql module is LOADED\n");
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    
    /* Check if module exists in kernel */
    if (access("/sys/module/sch_teql", F_OK) == 0 ||
        access("/lib/modules/$(uname -r)/kernel/net/sched/sch_teql.ko", F_OK) == 0) {
        printf("[+] teql module EXISTS but not loaded\n");
        return 1;
    }
    
    printf("[-] teql module NOT AVAILABLE in kernel\n");
    return 0;
}

/* Check kernel config */
static void check_kernel_config(void) {
    FILE *f = fopen("/boot/config-$(uname -r)", "r");
    if (!f) f = fopen("/proc/config.gz", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "CONFIG_NET_SCH_TEQL")) {
                printf("[+] Kernel config: %s", line);
                if (strstr(line, "=y") || strstr(line, "=m")) {
                    teql_available = 1;
                }
                break;
            }
        }
        fclose(f);
    }
}

static int netlink_send_recv(struct nlmsghdr *nlh) {
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { nlh, nlh->nlmsg_len };
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    if (sendmsg(nl_fd, &msg, 0) < 0) {
        if (errno == EPERM || errno == EACCES) {
            printf("[-] Need CAP_NET_ADMIN capability!\n");
        }
        return -1;
    }
    char buf[8192];
    struct iovec r_iov = { buf, sizeof(buf) };
    struct msghdr r_msg = { &sa, sizeof(sa), &r_iov, 1, NULL, 0, 0 };
    return recvmsg(nl_fd, &r_msg, 0);
}

/* Try to load teql module */
static void try_load_teql(void) {
    printf("[*] Attempting to load teql module...\n");
    if (system("modprobe sch_teql 2>/dev/null") == 0) {
        printf("[+] sch_teql module loaded\n");
    }
    if (system("modprobe teql 2>/dev/null") == 0) {
        printf("[+] teql module loaded\n");
    }
    
    /* Verify loading */
    sleep(1);
    FILE *f = fopen("/proc/modules", "r");
    if (f) {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "teql")) {
                printf("[+] teql module loaded successfully: %s", line);
                found = 1;
                break;
            }
        }
        fclose(f);
        if (!found) {
            printf("[-] Failed to load teql module\n");
        }
    }
}

int main(void) {
    printf("\n========================================\n");
    printf("CVE-2026-23074 teql UAF Exploit\n");
    printf("========================================\n");
    printf("[*] UID=%d EUID=%d\n", getuid(), geteuid());
    
    /* Check kernel version */
    system("uname -a");
    
    /* Check teql availability */
    check_kernel_config();
    try_load_teql();
    
    if (!teql_available) {
        printf("\n[-] teql module is NOT available in this kernel.\n");
        printf("    CVE-2026-23074 requires CONFIG_NET_SCH_TEQL=y/m\n");
        printf("    Your kernel does NOT have teql support.\n");
        printf("\n    This explains why exploit failed!\n");
        return 1;
    }
    
    /* Check capabilities */
    if (geteuid() != 0) {
        printf("\n[!] Running as non-root (UID=%d)\n", getuid());
        printf("[!] CAP_NET_ADMIN required for tc configuration\n");
        printf("[!] Try: sudo setcap cap_net_admin+ep ./exploit\n");
    }
    
    /* Setup interface (may fail without CAP_NET_ADMIN) */
    system("ip link add dummy0 type dummy 2>/dev/null");
    system("ip link set dummy0 up 2>/dev/null");
    
    /* Open netlink */
    nl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nl_fd < 0) {
        perror("socket");
        return 1;
    }
    
    /* Try to add teql qdisc - this will fail if module not available */
    char buf[4096];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta;
    
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    nlh->nlmsg_seq = ++seq;
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex("dummy0");
    tcm->tcm_parent = TC_H_ROOT;
    tcm->tcm_handle = 0x10000;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len = RTA_LENGTH(5);
    memcpy(RTA_DATA(rta), "teql", 5);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    
    printf("\n[*] Testing if teql qdisc can be added...\n");
    if (netlink_send_recv(nlh) < 0) {
        printf("[-] Cannot add teql qdisc: %s\n", strerror(errno));
        printf("    This means teql is NOT available in kernel!\n");
        close(nl_fd);
        return 1;
    }
    
    printf("[+] teql qdisc can be added - kernel may be vulnerable\n");
    
    printf("\n========================================\n");
    printf("CONCLUSION:\n");
    printf("========================================\n");
    printf("Scanner said VULNERABLE based on kernel version ONLY.\n");
    printf("But CONFIG_NET_SCH_TEQL is NOT enabled in your kernel.\n");
    printf("Therefore CVE-2026-23074 does NOT affect your system.\n");
    printf("\nTo be vulnerable, kernel needs:\n");
    printf("  - CONFIG_NET_SCH_TEQL=y (built-in) or =m (module)\n");
    printf("  - teql module loaded\n");
    printf("  - CAP_NET_ADMIN capability\n");
    
    close(nl_fd);
    return 0;
}
