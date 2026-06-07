#!/usr/bin/env python3
"""
Token — Windows token manipulation toolkit
Enumerate, duplicate, and elevate tokens via Python ctypes.
"""
import ctypes
import ctypes.wintypes
import sys
import os

# Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_IMPERSONATE = 0x0004
TOKEN_READ = 0x20008
TOKEN_ALL_ACCESS = 0xF01FF
SECURITY_IMPERSONATION_LEVEL = 2  # SecurityImpersonation
TOKEN_TYPE_PRIMARY = 1

# TokenInformationClass
TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenStatistics = 10
TokenIntegrityLevel = 25

# Error codes
ERROR_SUCCESS = 0
ERROR_NOT_FOUND = 1168

# SID name use
SidTypeUser = 1
SidTypeGroup = 2
SidTypeWellKnownGroup = 5

# Privilege constants
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001

# Integrity levels
SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
SECURITY_MANDATORY_LOW_RID = 0x00001000
SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
SECURITY_MANDATORY_HIGH_RID = 0x00003000
SECURITY_MANDATORY_SYSTEM_RID = 0x00004000

INTEGRITY_NAMES = {
    SECURITY_MANDATORY_UNTRUSTED_RID: "Untrusted",
    SECURITY_MANDATORY_LOW_RID: "Low",
    SECURITY_MANDATORY_MEDIUM_RID: "Medium",
    SECURITY_MANDATORY_HIGH_RID: "High",
    SECURITY_MANDATORY_SYSTEM_RID: "System",
}

KNOWN_PRIVILEGES = [
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeDebugPrivilege",
    "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeRelabelPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTimeZonePrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
]


def _get_proc_handle(pid):
    """Open a process with query access."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, False, pid)
    if not handle:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    return handle


def _get_token_handle(handle, access=TOKEN_QUERY | TOKEN_DUPLICATE):
    """Open the token associated with a process."""
    advapi32 = ctypes.windll.advapi32
    token = ctypes.wintypes.HANDLE()
    if not advapi32.OpenProcessToken(handle, access, ctypes.byref(token)):
        return None
    return token


def _sid_to_username(sid):
    """Convert a SID to DOMAIN\\USERNAME string."""
    advapi32 = ctypes.windll.advapi32
    name_len = ctypes.wintypes.DWORD(0)
    domain_len = ctypes.wintypes.DWORD(0)
    use = ctypes.wintypes.DWORD()

    # First call to get buffer sizes
    advapi32.LookupAccountSidW(None, sid, None, ctypes.byref(name_len),
                               None, ctypes.byref(domain_len), ctypes.byref(use))

    name = ctypes.create_unicode_buffer(name_len.value)
    domain = ctypes.create_unicode_buffer(domain_len.value)

    if advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(name_len),
                                  domain, ctypes.byref(domain_len), ctypes.byref(use)):
        return f"{domain.value}\\{name.value}"
    return None


def _get_token_user(token_handle):
    """Get the user SID from a token."""
    advapi32 = ctypes.windll.advapi32

    # First call to get buffer size
    size = ctypes.wintypes.DWORD(0)
    advapi32.GetTokenInformation(token_handle, TokenUser, None, 0, ctypes.byref(size))
    if not size.value:
        return None

    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token_handle, TokenUser, buf, size.value, ctypes.byref(size)):
        return None

    # TOKEN_USER structure: SID_AND_ATTRIBUTES { SID* User; DWORD Attributes }
    # First 4/8 bytes is the SID pointer, next 4 bytes is attributes
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    sid_ptr = ctypes.c_void_p()
    ctypes.memmove(ctypes.byref(sid_ptr), buf, ptr_size)

    if not sid_ptr:
        return None

    username = _sid_to_username(sid_ptr)
    return username or "UNKNOWN"


def _get_token_integrity(token_handle):
    """Get the integrity level SID from a token."""
    advapi32 = ctypes.windll.advapi32

    size = ctypes.wintypes.DWORD(0)
    advapi32.GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, ctypes.byref(size))
    if not size.value:
        return None

    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token_handle, TokenIntegrityLevel, buf, size.value, ctypes.byref(size)):
        return None

    # TOKEN_MANDATORY_LABEL = SID_AND_ATTRIBUTES
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    sid_ptr = ctypes.c_void_p()
    ctypes.memmove(ctypes.byref(sid_ptr), buf, ptr_size)

    if not sid_ptr:
        return None

    # Get the SID subauthority (last RID = integrity level)
    # SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority[]
    sub_auth_count = ctypes.c_ubyte.from_address(sid_ptr.value + 1).value
    if sub_auth_count == 0:
        return None

    # Each subauthority is 4 bytes, last one at offset: 8 + (count-1)*4
    offset = 8 + (sub_auth_count - 1) * 4
    rid = ctypes.c_uint32.from_address(sid_ptr.value + offset).value

    return INTEGRITY_NAMES.get(rid, f"RID {rid:#x}")


def _get_token_privileges(token_handle):
    """Get the list of privileges from a token."""
    advapi32 = ctypes.windll.advapi32

    size = ctypes.wintypes.DWORD(0)
    advapi32.GetTokenInformation(token_handle, TokenPrivileges, None, 0, ctypes.byref(size))
    if not size.value:
        return []

    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token_handle, TokenPrivileges, buf, size.value, ctypes.byref(size)):
        return []

    # TOKEN_PRIVILEGES: DWORD PrivilegeCount + LUID_AND_ATTRIBUTES Privileges[]
    count = ctypes.c_uint32.from_buffer(buf, 0).value
    privs = []

    for i in range(count):
        # LUID_AND_ATTRIBUTES: LUID (8 bytes) + Attributes (4 bytes)
        offset = 4 + i * 12
        luid_low = ctypes.c_uint32.from_buffer(buf, offset).value
        luid_high = ctypes.c_uint32.from_buffer(buf, offset + 4).value
        attrs = ctypes.c_uint32.from_buffer(buf, offset + 8).value

        luid = (luid_high << 32) | luid_low

        # Lookup privilege name from LUID
        name_len = ctypes.wintypes.DWORD(0)
        advapi32.LookupPrivilegeNameW(None, ctypes.byref(ctypes.c_uint64(luid)),
                                      None, ctypes.byref(name_len))
        if name_len.value:
            name_buf = ctypes.create_unicode_buffer(name_len.value)
            if advapi32.LookupPrivilegeNameW(None, ctypes.byref(ctypes.c_uint64(luid)),
                                             name_buf, ctypes.byref(name_len)):
                name = name_buf.value
                enabled = bool(attrs & SE_PRIVILEGE_ENABLED)
                privs.append((name, enabled, attrs))

    return privs


def _get_process_name(pid):
    """Get the executable name for a PID."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    buf = ctypes.create_unicode_buffer(260)
    size = ctypes.wintypes.DWORD(260)
    if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        kernel32.CloseHandle(handle)
        return os.path.basename(buf.value)

    kernel32.CloseHandle(handle)
    return None


def list_tokens():
    """List all processes with their token information."""
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    # Get list of PIDs
    size = 1024
    pids = (ctypes.wintypes.DWORD * size)()
    needed = ctypes.wintypes.DWORD()
    psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed))
    count = needed.value // ctypes.sizeof(ctypes.wintypes.DWORD)

    results = []
    for i in range(min(count, size)):
        pid = pids[i]
        if pid == 0:
            continue

        proc_name = _get_process_name(pid)
        handle = _get_proc_handle(pid)
        if not handle:
            continue

        token = _get_token_handle(handle, TOKEN_QUERY)
        if not token:
            kernel32.CloseHandle(handle)
            continue

        username = _get_token_user(token)
        integrity = _get_token_integrity(token)
        privs = _get_token_privileges(token)

        enabled_count = sum(1 for p in privs if p[1])
        high_value_privs = [p[0] for p in privs if p[1] and p[0] in
                           {"SeDebugPrivilege", "SeImpersonatePrivilege",
                            "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege",
                            "SeBackupPrivilege", "SeRestorePrivilege",
                            "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege"}]

        results.append({
            "pid": pid,
            "name": proc_name or f"PID {pid}",
            "user": username or "?",
            "integrity": integrity or "?",
            "privs_total": len(privs),
            "privs_enabled": enabled_count,
            "high_value": high_value_privs,
        })

        kernel32.CloseHandle(token.value)
        kernel32.CloseHandle(handle)

    return results


def print_token_table(results):
    """Print token results in a formatted table."""
    if not results:
        print("No processes found.")
        return

    header = f"{'PID':>6}  {'Image':<20} {'User':<25} {'Integrity':<12} {'Privs':<6} {'High-Value':<30}"
    print(header)
    print("-" * len(header))

    for r in sorted(results, key=lambda x: (x["integrity"] != "System",
                                            x["integrity"] != "High",
                                            x["integrity"] != "Medium",
                                            x["integrity"] != "Low", -x["pid"])):
        hv = ", ".join(r["high_value"][:3]) if r["high_value"] else "-"
        privs_str = f"{r['privs_enabled']}/{r['privs_total']}"
        il = r["integrity"]
        print(f"{r['pid']:>6}  {r['name']:<20} {r['user']:<25} {il:<12} {privs_str:<6} {hv:<30}")


def whoami():
    """Show current process token info."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetCurrentProcess()
    if not handle:
        print("[-] GetCurrentProcess failed")
        return

    token = _get_token_handle(handle, TOKEN_QUERY)
    if not token:
        print("[-] OpenProcessToken failed")
        return

    username = _get_token_user(token)
    integrity = _get_token_integrity(token)
    privs = _get_token_privileges(token)

    print(f"User:       {username}")
    print(f"Integrity:  {integrity}")
    print(f"PID:        {kernel32.GetCurrentProcessId()}")
    print()
    print("Privileges:")
    print(f"  {'Status':<12} {'Name':<40}")
    print(f"  {'-'*12} {'-'*40}")
    for name, enabled, _ in sorted(privs):
        status = "ENABLED" if enabled else "disabled"
        print(f"  {status:<12} {name}")
    print(f"\n  Total: {len(privs)} ({sum(1 for _, e, _ in privs if e)} enabled)")

    kernel32.CloseHandle(token.value)


def dup_token(pid, command):
    """Duplicate token from a process and run command with it."""
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    handle = _get_proc_handle(pid)
    if not handle:
        print(f"[-] Cannot open PID {pid} ({ctypes.GetLastError()})")
        return False

    token = _get_token_handle(handle, TOKEN_QUERY | TOKEN_DUPLICATE)
    if not token:
        print(f"[-] Cannot open token for PID {pid}")
        kernel32.CloseHandle(handle)
        return False

    dup = ctypes.wintypes.HANDLE()
    if not advapi32.DuplicateTokenEx(token, TOKEN_ALL_ACCESS, None,
                                     SECURITY_IMPERSONATION_LEVEL,
                                     TOKEN_TYPE_PRIMARY,
                                     ctypes.byref(dup)):
        print(f"[-] DuplicateTokenEx failed ({ctypes.GetLastError()})")
        kernel32.CloseHandle(token.value)
        kernel32.CloseHandle(handle)
        return False

    si = ctypes.c_byte * ctypes.sizeof(ctypes.wintypes.STARTUPINFOW)
    startup_info = si()
    ctypes.windll.kernel32.GetStartupInfoW(ctypes.byref(ctypes.c_void_p.from_buffer(startup_info)))

    pi = ctypes.c_byte * ctypes.sizeof(ctypes.wintypes.PROCESS_INFORMATION)
    proc_info = pi()

    username = _get_token_user(dup)

    success = advapi32.CreateProcessWithTokenW(
        dup,
        0,
        None,
        command,
        0,
        None,
        None,
        ctypes.byref(startup_info),
        ctypes.byref(proc_info)
    )

    if success:
        print(f"[+] Token duplicated from PID {pid} ({username})")
        print(f"[+] Process created: {command}")
        kernel32.CloseHandle(ctypes.c_void_p.from_buffer(proc_info, 0).value)  # hProcess
        kernel32.CloseHandle(ctypes.c_void_p.from_buffer(proc_info, ctypes.sizeof(ctypes.c_void_p)).value)  # hThread
    else:
        print(f"[-] CreateProcessWithTokenW failed ({ctypes.GetLastError()})")

    kernel32.CloseHandle(dup)
    kernel32.CloseHandle(token.value)
    kernel32.CloseHandle(handle)
    return success


def list_privs():
    """List all available privileges on the system."""
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    handle = kernel32.GetCurrentProcess()
    token = _get_token_handle(handle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)
    if not token:
        print("[-] OpenProcessToken failed")
        return

    privs = _get_token_privileges(token)
    print(f"{'Enabled':<12} {'Name':<45}")
    print("-" * 57)
    for name, enabled, _ in sorted(privs):
        status = "ENABLED" if enabled else "disabled"
        print(f"{status:<12} {name}")

    print(f"\nTotal: {len(privs)} ({sum(1 for _, e, _ in privs if e)} enabled)")
    kernel32.CloseHandle(token.value)


def enable_priv(priv_name, enable=True):
    """Enable or disable a privilege in the current process token."""
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    handle = kernel32.GetCurrentProcess()
    token = _get_token_handle(handle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)
    if not token:
        print(f"[-] OpenProcessToken failed ({ctypes.GetLastError()})")
        return False

    # Lookup LUID for privilege name
    luid = ctypes.c_uint64()
    if not advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
        print(f"[-] Unknown privilege: {priv_name}")
        kernel32.CloseHandle(token.value)
        return False

    # TOKEN_PRIVILEGES structure: DWORD PrivilegeCount + LUID_AND_ATTRIBUTES Privileges[1]
    buf = ctypes.create_string_buffer(4 + 12)
    ctypes.memmove(buf, ctypes.byref(ctypes.c_uint32(1)), 4)
    ctypes.memmove(ctypes.byref(buf, 4), ctypes.byref(luid), 8)

    attr = SE_PRIVILEGE_ENABLED if enable else 0
    ctypes.memmove(ctypes.byref(buf, 12), ctypes.byref(ctypes.c_uint32(attr)), 4)

    old_size = ctypes.wintypes.DWORD(0)
    success = advapi32.AdjustTokenPrivileges(token, False, buf, ctypes.sizeof(buf),
                                             None, ctypes.byref(old_size))
    err = kernel32.GetLastError()

    if success and err == ERROR_SUCCESS:
        action = "enabled" if enable else "disabled"
        print(f"[+] {priv_name} {action}")
        kernel32.CloseHandle(token.value)
        return True

    if err == ERROR_NOT_FOUND:
        print(f"[-] {priv_name} not held by current token")
    else:
        print(f"[-] AdjustTokenPrivileges failed ({err})")

    kernel32.CloseHandle(token.value)
    return False


def check_privesc():
    """Check for common privilege escalation vectors."""
    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    handle = kernel32.GetCurrentProcess()
    token = _get_token_handle(handle, TOKEN_QUERY)
    if not token:
        print("[-] Cannot open token")
        return

    username = _get_token_user(token)
    integrity = _get_token_integrity(token)
    privs = _get_token_privileges(token)
    priv_names = [p[0] for p in privs]
    enabled_privs = {p[0] for p in privs if p[1]}

    print(f"User:       {username}")
    print(f"Integrity:  {integrity}")
    print()

    # Check high-value privileges
    checks = [
        ("SeDebugPrivilege", "Can debug any process (potential privilege escalation)"),
        ("SeImpersonatePrivilege", "Can impersonate any token (JuicyPotato-like)"),
        ("SeAssignPrimaryTokenPrivilege", "Can assign primary token (potato attacks)"),
        ("SeTcbPrivilege", "Act as part of OS (full system control)"),
        ("SeBackupPrivilege", "Can read any file (regback, SAM/SYSTEM dump)"),
        ("SeRestorePrivilege", "Can write any file"),
        ("SeTakeOwnershipPrivilege", "Can take ownership of any object"),
        ("SeLoadDriverPrivilege", "Can load/unload device drivers"),
        ("SeCreateTokenPrivilege", "Can create arbitrary tokens"),
    ]

    found_interesting = False
    print("Privilege Escalation Vectors:")
    for priv, desc in checks:
        if priv in priv_names:
            status = "ENABLED" if priv in enabled_privs else "disabled"
            icon = "[!]" if priv in enabled_privs else "[.]"
            print(f"  {icon} {priv:<30} {status:<10} {desc}")
            found_interesting = True

    if not found_interesting:
        print("  No high-value privileges found.")

    # Check integrity level
    print()
    if integrity in ("System", "High"):
        print("[+] Already running at elevated integrity")
    elif integrity == "Medium":
        print("[.] Running at Medium integrity — elevation required for admin tasks")
    elif integrity == "Low":
        print("[!] Running at Low integrity — heavily restricted")
    elif integrity == "Untrusted":
        print("[!] Running at Untrusted integrity — sandboxed")

    kernel32.CloseHandle(token.value)


def require_admin():
    """Check if running as admin and exit if not."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Administrator privileges required")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: token <command> [args]")
        print()
        print("Commands:")
        print("  list              List processes with token info")
        print("  whoami            Show current token details")
        print("  dup <pid> <cmd>   Duplicate token and run command")
        print("  privs [list]      List current privileges")
        print("  privs enable <p>  Enable a privilege")
        print("  privs disable <p> Disable a privilege")
        print("  check             Check privesc vectors")
        return

    cmd = sys.argv[1].lower()

    if cmd == "list":
        results = list_tokens()
        print_token_table(results)

    elif cmd == "whoami":
        whoami()

    elif cmd == "dup":
        if len(sys.argv) < 4:
            print("Usage: token dup <pid> <command>")
            return
        require_admin()
        pid = int(sys.argv[2])
        command = " ".join(sys.argv[3:])
        dup_token(pid, command)

    elif cmd == "privs":
        if len(sys.argv) == 2:
            list_privs()
        elif len(sys.argv) >= 4:
            require_admin()
            action = sys.argv[2].lower()
            priv_name = sys.argv[3]
            if action == "enable":
                enable_priv(priv_name, True)
            elif action == "disable":
                enable_priv(priv_name, False)
            else:
                print("Usage: token privs <enable|disable> <privilege_name>")
        else:
            print("Usage: token privs [enable|disable <privilege>]")

    elif cmd == "check":
        check_privesc()

    else:
        print(f"[-] Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
