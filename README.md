# Token

Windows token manipulation toolkit — enumerate, duplicate, and elevate access tokens via Python ctypes.

```
token list              # list processes with integrity level and user
token whoami            # show current token info and privileges
token dup <pid> <cmd>   # duplicate token from process and run command
token privs [enable|disable|list] [privilege]
token check             # check privilege escalation vectors
```

Zero dependencies — uses ctypes directly.

---

### Installation

```powershell
git clone https://github.com/pythernel/token
cd token
python token.py list
```

### Examples

```powershell
# Inspect available tokens
token list

# Run PowerShell as SYSTEM via duplicate token
token dup 4 powershell

# Enable SeDebugPrivilege in current process
token privs enable SeDebugPrivilege

# Check for privesc opportunities
token check
```

---

### Requirements

- Python 3.6+
- Windows (tested 10/11)
- Administrator rights for: `dup`, `privs enable`, `check` (partial)
