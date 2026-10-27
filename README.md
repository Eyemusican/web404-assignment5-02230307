# WEB404 Secure Coding Practices � Assignment 5

**Student:** Tenzin Namgay
**Student ID:** 02230307

## Topic

Nikto Vulnerability Scan

## What I did

I used Nikto to scan my Assignment 4 app (the SQL injection project) while
it was running on my laptop, and looked at what it found. The full
explanation of each finding is in docs/REPORT.md.

## Tool used

Nikto v2.1.5, installed and run from WSL (Ubuntu)

## Target

My own Assignment 4 app, Node.js + Express + SQLite, running locally on
port 3000. I only scanned my own app, not a live website.

## How to run it again

Start the app (on Windows, in the Assignment 4 folder):

```bash
cd web404-assignment4
npm install
npm run seed
npm start
```

Install Nikto (WSL):

```bash
sudo apt update
sudo apt install nikto
```

Since WSL sees "localhost" as itself and not Windows, I had to scan the
Windows host IP instead:

```bash
ip route show default | awk '{print $3}'
```

That gave me 172.18.0.1 on my machine. Then I ran:

```bash
nikto -h http://172.18.0.1:3000 -o nikto-scan.txt
```

The scan took about 12 seconds and found 7 things worth reporting.

## What it found

| # | Finding | Severity |
|---|---|---|
| 1 | X-Powered-By header reveals Express | Low |
| 2 | ETag flagged as leaking inodes (false positive) | Info |
| 3 | X-Frame-Options header missing | Low to Medium |
| 4 | Content-Security-Policy found, only on the 404 page | Info |
| 5 | X-Content-Type-Options found, only on the 404 page | Info |
| 6 | Allowed methods on / are GET and HEAD | Info |
| 7 | /login/ flagged as interesting | Info |

Full explanation of each one, why it matters (or doesn't), and how to fix
it is in docs/REPORT.md.

## Files in this repo

- docs/REPORT.md � full report
- nikto-scan.txt � raw scan output
- screenshots/ � scan screenshots
