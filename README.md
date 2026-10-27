# WEB404 Secure Coding Practices — Assignment 5

**Student:** Tenzin Namgay (Cuney)
**Student ID:** 02230307

## Topic

**Web Server Scanning with Nikto**

Using Nikto to scan a sample website and interpret the findings. The full
write-up, with one section per finding, is in [docs/REPORT.md](docs/REPORT.md).

## Tool

- **Nikto v2.1.5**, an open source web server scanner, run from WSL (Ubuntu)

## Target

My Assignment 4 app: a deliberately vulnerable Node.js + Express + SQLite
SQL injection demo, running locally on port 3000.

| Item | Value |
|---|---|
| App | `web404-assignment4` (`npm start`) |
| URL from Windows | `http://localhost:3000` |
| URL scanned from WSL | `http://172.18.0.1:3000` (Windows host as seen from WSL) |

> ⚠️ Only scan systems you own or have permission to test. The target here
> is my own app running on my own machine.

## Reproducing the scan

### 1. Start the target app (Windows, in the Assignment 4 folder)

```bash
cd web404-assignment4
npm install
npm run seed
npm start          # app on http://localhost:3000
```

### 2. Install Nikto (WSL / Ubuntu)

```bash
sudo apt update
sudo apt install nikto
nikto -Version
```

### 3. Find the Windows host IP from WSL

Inside WSL, `localhost` is the Linux VM, not Windows, so scan the Windows
host's address instead:

```bash
ip route show default | awk '{print $3}'    # printed 172.18.0.1 on my machine
```

Check the app is reachable:

```bash
curl -I http://172.18.0.1:3000
```

(If this times out, allow Node.js through Windows Firewall.)

### 4. Run the scan

```bash
cd /mnt/c/Users/Tenzin/web404-assignment5-02230307
nikto -h http://172.18.0.1:3000 -o nikto-scan.txt
cat nikto-scan.txt
```

- `-h` sets the target URL
- `-o` writes the findings to a file (the `.txt` extension picks plain text)

The scan takes about 12 seconds and reports 7 items.

## Findings at a glance

| # | Finding | Severity |
|---|---|---|
| 1 | `X-Powered-By: Express` header reveals the framework | Low |
| 2 | ETag "inode leak" (false positive for Express) | Info |
| 3 | `X-Frame-Options` missing (clickjacking) | Low–Medium |
| 4 | `Content-Security-Policy` found, only on the 404 page | Info |
| 5 | `X-Content-Type-Options: nosniff` found, only on the 404 page | Info |
| 6 | Allowed methods on `/`: GET, HEAD | Info |
| 7 | `/login/` flagged as interesting | Info |

See [docs/REPORT.md](docs/REPORT.md) for what each one means and how to fix it.

## Repository contents

| Path | Contents |
|---|---|
| [docs/REPORT.md](docs/REPORT.md) | Assignment report |
| [nikto-scan.txt](nikto-scan.txt) | Raw Nikto output |
| [screenshots/](screenshots/) | Scan command and output screenshots |
