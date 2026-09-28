#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  S U B F I N D E R  ·  merged reconnaissance engine   (Kali Linux / Python 3)
# -----------------------------------------------------------------------------
#  Module order : curl(public IP) -> ifconfig -> curl(HTTP audit) ->
#                 whatweb -> whois -> subfinder -> nmap -> executive summary
#  Style rule   : NO colour. Everything before the first ':' or '—' is
#                 rendered BOLD + ITALIC. Everything after is plain.
#  Save rule    : Asks once whether to save a timestamped .txt report.
#  Scan rule    : Asks which TCP/UDP scan technique to use (-sS/-sT/-sA/...).
#  Run as       : sudo python3 webrecon.py
# =============================================================================

# ----------------------------- standard library ------------------------------
import os          # os.geteuid() -> are we root? (affects nmap capabilities)
import re          # regex engine, used to parse every tool's raw output
import sys         # stdout redirection + clean exit codes
import json        # parses the ipinfo.io JSON response
import shutil      # shutil.which() -> "is this binary installed?"
import ipaddress   # RFC1918 / private-range detection
import subprocess  # launches curl / ifconfig / subfinder / nmap / whatweb / whois
import xml.etree.ElementTree as ET   # parses `nmap -oX -` XML output
from datetime import datetime        # timestamps the saved report file

# ----------------------------- style tokens ----------------------------------
B = "\033[1m"      # bold ON
I = "\033[3m"      # italic ON
R = "\033[0m"      # reset every attribute

ANSI_RE = re.compile(r"\033\[[0-9;]*m")   # strips ANSI codes for the report file

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "   # browser ident
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")      # chrome version tail

STATE = {"public_ip": None}   # holds the discovered egress IP or None
FINDINGS = []                 # list of (severity, message) tuples

# Menu of scan techniques. Key is the number the operator types.
SCAN_TYPES = {
    "1": ("-sS", "SYN stealth scan (needs root, default, fastest)"),
    "2": ("-sT", "TCP connect scan (no root needed, uses connect())"),
    "3": ("-sA", "ACK scan (maps firewall rules, no port state)"),
    "4": ("-sW", "Window scan (TCP window size, distinguishes open/closed)"),
    "5": ("-sN", "NULL scan (no TCP flags set, evades some filters)"),
    "6": ("-sF", "FIN scan (only FIN set, evades some filters)"),
    "7": ("-sX", "Xmas scan (FIN+PSH+URG set, evades some filters)"),
    "8": ("-sU", "UDP scan (slow, finds DNS/SNMP/DHCP services)"),
}


# =============================================================================
#  STYLE HELPERS
# =============================================================================

def style_split(text):
    # Bold+italic everything before the first ':' or em-dash; leave the rest plain.
    colon = text.find(":")                            # index of first colon or -1
    dash = text.find("—")                             # index of first em-dash or -1
    cuts = [c for c in (colon, dash) if c != -1]      # keep separators that exist
    if not cuts:                                      # no separator found?
        return text                                   # return text untouched
    cut = min(cuts)                                   # earliest separator wins
    return f"{B}{I}{text[:cut].rstrip()}{R}{text[cut:]}"   # styled prefix + tail


# =============================================================================
#  OUTPUT PLUMBING
# =============================================================================

class Tee:
    # Mirror everything printed to the terminal into a plain-text report file.
    def __init__(self, path):                         # constructor takes path
        self.fh = open(path, "w", encoding="utf-8")   # open report for writing
    def write(self, data):                            # called by print()
        sys.__stdout__.write(data)                    # real terminal gets ANSI
        self.fh.write(ANSI_RE.sub("", data))          # file gets clean text
    def flush(self):                                  # called by print()
        sys.__stdout__.flush()                        # flush terminal buffer
        self.fh.flush()                               # flush file buffer
    def close(self):                                  # called at shutdown
        self.fh.close()                               # release file handle


def banner():
    # One-time identity block. No fluff, just the engine name.
    print(f"{B}{I}")                                  # turn on bold + italic
    print("  +==================================================================+")
    print("  |  S U B F I N D E R  -  RECON INTELLIGENCE ENGINE                 |")
    print("  |  curl . ifconfig . whatweb . whois . subfinder . nmap            |")
    print("  +==================================================================+")
    print(f"{R}")                                     # reset styling


def section(idx, title):
    # Numbered section divider.
    bar = "=" * 70                                    # heavy rule of '='
    print(f"\n{B}{bar}{R}")                           # print rule in bold
    print(f"{B}{I}  [{idx}]  {title.upper()}{R}")     # numbered upper-case title
    print(f"{B}{bar}{R}")                             # print rule again


def bullet(label, value=""):
    # One top-level bullet: '- LABEL: value' with the label styled.
    if value == "":                                   # no value supplied?
        print(f"- {style_split(label)}")              # label-only bullet
    else:                                             # value supplied?
        print(f"- {B}{I}{label}{R}: {value}")         # label + value bullet


def sub(text):
    # One nested bullet, prefix before ':' or em-dash is styled.
    print(f"    - {style_split(text)}")              # four-space indent + dash


def ask(prompt, default=""):
    # Simple prompt helper; returns default on empty input or EOF.
    try:                                              # input may raise EOF
        ans = input(f"{B}{I}{prompt}{R} ").strip()    # show prompt, read line
    except EOFError:                                  # non-interactive stdin
        ans = ""                                      # treat as empty
    return ans if ans else default                    # fall back to default


def run(cmd, timeout=600):
    # Safe subprocess wrapper. Returns (stdout, stderr, returncode).
    try:                                              # catch expected errors
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except FileNotFoundError:                         # binary not installed
        return "", f"{cmd[0]}: not installed", 127
    except subprocess.TimeoutExpired:                 # ran too long
        return "", f"{cmd[0]}: timed out", 124


def is_private_ip(v):
    # True when v is an RFC1918 / loopback / link-local address.
    try:                                              # ipaddress may raise
        return ipaddress.ip_address(v).is_private
    except ValueError:                                # not an IP at all
        return False


def looks_like_domain(v):
    # True when v looks like a DNS name (has a dot, not an IP).
    if is_private_ip(v):                              # private IP -> not domain
        return False
    try:                                              # try to parse as IP
        ipaddress.ip_address(v)                       # parses -> it's a raw IP
        return False
    except ValueError:                                # not an IP, likely a name
        return "." in v                               # domains have a dot


# =============================================================================
#  [1] PUBLIC IP  —  curl only
# =============================================================================

def module_public_ip():
    # Discover egress IP and its geo/ASN enrichment.
    section(1, "public ip / egress identity")
    ip = None                                         # holder for the IP
    for url in ("https://ifconfig.me/ip",             # endpoint #1
                "https://api.ipify.org",              # endpoint #2
                "https://ipinfo.io/ip"):              # endpoint #3
        out, err, rc = run(["curl", "-s", "--max-time", "10", url])
        if rc == 0 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", out or ""):
            ip = out                                  # remember the IP
            bullet("Public IP", ip)                   # print the IP
            bullet("Resolved via", url)               # print the endpoint
            break                                     # stop on first success
    if not ip:                                        # every endpoint failed
        bullet("Public IP", "unavailable (no egress / curl blocked)")
        return
    STATE["public_ip"] = ip                           # cache for whois module
    out, err, rc = run(["curl", "-s", "--max-time", "10",
                        f"https://ipinfo.io/{ip}/json"])
    if rc == 0 and out:                               # only parse on success
        try:                                          # JSON may be malformed
            data = json.loads(out)                    # parse the JSON blob
            for k in ("hostname", "city", "region", "country",
                      "loc", "org", "timezone"):      # useful keys
                if data.get(k):                       # key present & truthy?
                    bullet(k.capitalize(), data[k])   # print bullet
        except json.JSONDecodeError:                  # malformed JSON
            bullet("Geo/ASN enrichment", "unavailable")


# =============================================================================
#  [2] IFCONFIG  —  local interfaces, parsed, zero fluff
# =============================================================================

def parse_ifconfig(text):
    # Turn raw `ifconfig -a` output into a list of interface dictionaries.
    ifaces = []                                       # accumulator
    cur = None                                        # interface being filled
    for line in text.splitlines():                    # iterate output lines
        if not line.strip():                          # blank line
            continue                                  # skip separators
        if not line[0].isspace():                     # header line = new iface
            m = re.match(r"^(\S+?):\s+flags=\d+<([^>]*)>(?:\s+mtu\s+(\d+))?", line)
            if m:                                     # header matched
                cur = {"name": m.group(1),            # e.g. eth0
                       "flags": m.group(2).split(","),   # UP,RUNNING,...
                       "mtu": m.group(3) or "?",      # MTU value
                       "inet": [], "inet6": [], "mac": None}
                ifaces.append(cur)                    # register interface
            else:                                     # unrecognised header
                cur = None                            # stop filling previous
        elif cur is not None:                         # detail line
            s = line.strip()                          # trim whitespace
            m = re.match(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", s)
            if m: cur["inet"].append(m.group(1)); continue
            m = re.match(r"inet6 (?:addr: )?([0-9a-fA-F:]+)", s)
            if m: cur["inet6"].append(m.group(1)); continue
            m = re.match(r"ether ([0-9a-fA-F:]{17})", s)
            if m: cur["mac"] = m.group(1)             # hardware address
    return ifaces                                     # hand back the list


def module_ifconfig():
    # Dump every local interface as a tight bullet list, no noise.
    section(2, "local interfaces (ifconfig, no fluff)")
    if shutil.which("ifconfig"):                      # preferred tool present?
        raw, err, rc = run(["ifconfig", "-a"])        # ask for all interfaces
    else:                                             # modern fallback
        raw, err, rc = run(["ip", "-o", "addr"])      # use iproute2 instead
        bullet("Note", "ifconfig missing - used `ip -o addr` instead")
    if not raw:                                       # nothing captured
        bullet("Interfaces", "no output (run with sufficient privileges)")
        return
    for iface in parse_ifconfig(raw):                 # loop each interface
        state = "UP" if "UP" in iface["flags"] else "DOWN"
        bullet(f"Interface {iface['name']} [{state}]",
               ", ".join(f for f in iface["flags"] if f != "UP"))
        for a in iface["inet"]:  sub(f"IPv4: {a}")    # each IPv4
        for a in iface["inet6"]: sub(f"IPv6: {a}")    # each IPv6
        if iface["mac"]:         sub(f"MAC: {iface['mac']}")
        sub(f"MTU: {iface['mtu']}")                   # always show MTU


# =============================================================================
#  [3] CURL HTTP HEADER AUDIT
# =============================================================================

SECURITY_HEADERS = {                                  # expected security headers
    "Strict-Transport-Security": "forces HTTPS on all future requests",
    "Content-Security-Policy":   "blocks XSS / injection payload delivery",
    "X-Frame-Options":           "blocks clickjacking via iframes",
    "X-Content-Type-Options":    "blocks MIME-type sniffing",
    "Referrer-Policy":           "controls referrer leakage to third parties",
    "Permissions-Policy":        "locks down browser feature access",
    "X-XSS-Protection":          "legacy reflected-XSS filter",
    "Cross-Origin-Opener-Policy":   "isolates the browsing context",
    "Cross-Origin-Resource-Policy": "blocks cross-origin resource reads",
    "Cross-Origin-Embedder-Policy": "blocks cross-origin embedding",
}


def parse_header_blocks(raw):
    # Split a `curl -D -` dump into [(status_line, {header: value}), ...].
    blocks = []                                       # accumulator
    for chunk in re.split(r"\r?\n\r?\n+", raw.strip()):   # split on blank lines
        lines = [l for l in chunk.splitlines() if l.strip()]
        if not lines or not lines[0].upper().startswith("HTTP/"):
            continue                                  # not a header block
        status = lines[0].strip()                     # first line is status
        headers = {}                                  # header dictionary
        for line in lines[1:]:                        # remaining lines
            if ":" in line:                           # valid header line?
                k, v = line.split(":", 1)             # split on first colon
                headers[k.strip()] = v.strip()        # store key -> value
        blocks.append((status, headers))              # add this block
    return blocks


def probe_url(url):
    # Fetch headers with curl and report status, redirects and header audit.
    raw, err, rc = run(["curl", "-s", "-k", "-L", "-o", "/dev/null",
                        "-D", "-", "--max-time", "15", "-A", UA, url])
    if rc != 0 or not raw:                            # curl failed or empty?
        bullet(f"URL {url}", "unreachable"); return False
    blocks = parse_header_blocks(raw)                 # every hop in the chain
    if not blocks:                                    # no parseable headers
        bullet(f"URL {url}", "no HTTP response"); return False
    status, headers = blocks[-1]                      # final response wins
    lower = {k.lower(): v for k, v in headers.items()}   # case-insensitive map
    bullet("URL", url)                                # print the URL
    bullet("Final status", status)                    # final status line
    bullet("Redirect hops", str(max(0, len(blocks) - 1)))
    body, _, _ = run(["curl", "-s", "-k", "-L", "--max-time", "15", "-A", UA, url])
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if m:                                             # title matched?
        bullet("Page title", re.sub(r"\s+", " ", m.group(1)).strip()[:90])
    if headers:                                       # any headers at all?
        bullet("Headers returned", str(len(headers))) # count
        for k, v in headers.items(): sub(f"{k}: {v[:120]}")
    present = [h for h in SECURITY_HEADERS if h.lower() in lower]   # included
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower]# missing
    bullet("Security headers INCLUDED", f"{len(present)}/{len(SECURITY_HEADERS)}")
    for h in present: sub(f"{h}: {lower[h.lower()]}  -  {SECURITY_HEADERS[h]}")
    bullet("Security headers MISSING", f"{len(missing)}/{len(SECURITY_HEADERS)}")
    for h in missing: sub(f"{h}: {SECURITY_HEADERS[h]}")
    if missing:                                       # any missing headers?
        FINDINGS.append(("MEDIUM", f"{len(missing)} security headers absent on {url}"))
    return True


def module_http(target):
    # Audit http:// and https:// header sets for the target.
    section(3, "curl http header audit")
    if not shutil.which("curl"):                      # curl is mandatory
        bullet("curl", "NOT INSTALLED - run: sudo apt install curl"); return
    host = re.sub(r"^https?://", "", target).split("/")[0]
    for scheme in ("http", "https"):                  # try both schemes
        probe_url(f"{scheme}://{host}/")              # audit each one


# =============================================================================
#  [4] WHATWEB
# =============================================================================

def module_whatweb(target):
    # Fingerprint web technologies with whatweb, printed as clean bullets.
    section(4, "whatweb technology fingerprint")
    if not shutil.which("whatweb"):                   # optional tool present?
        bullet("whatweb", "NOT INSTALLED - run: sudo apt install whatweb"); return
    cmd = ["whatweb", "-a", "3", "--color=never", "--no-errors",
           f"http://{target}/"]                       # aggressive, no colour
    out, err, rc = run(cmd, timeout=180)              # 3-minute cap
    if not out: bullet("whatweb", "no fingerprint returned"); return
    seen = set()                                      # de-duplication set
    for name, value in re.findall(r"([A-Za-z][A-Za-z0-9_\-]*)\[([^\[\]]*)\]", out):
        pair = (name, value)                          # tuple for the set
        if pair in seen: continue                     # skip duplicates
        seen.add(pair); bullet(name, value)           # styled name, plain value
    if not seen: bullet("whatweb", "no plugins matched")


# =============================================================================
#  [5] WHOIS
# =============================================================================

WHOIS_KEYS = {                                        # registry fields we keep
    "domain name","registrar","registrar url","creation date","updated date",
    "expiry date","registry expiry date","name server","dnssec","status",
    "registrant organization","registrant country",
    "netrange","cidr","netname","orgname","organization","orgid",
    "country","regdate","updated","abuseemail","orgabuseemail",
    "orgabusename","descr","inetnum","route","origin","mnt-by",
    "referral server","address","e-mail",
}


def module_whois(target):
    # Query the registry for the target, or fall back to the egress IP.
    section(5, "whois registry lookup")
    if not shutil.which("whois"):                     # optional tool present?
        bullet("whois", "NOT INSTALLED - run: sudo apt install whois"); return
    query = target                                    # what we query
    if is_private_ip(target):                         # RFC1918 has no registry
        bullet("Note", "target is a private RFC1918 address - no registry entry")
        if STATE["public_ip"]:                        # we have a public IP?
            query = STATE["public_ip"]                # fall back to it
            bullet("Fallback query", query)           # announce fallback
        else:
            bullet("whois", "skipped - no public IP available"); return
    out, err, rc = run(["whois", query], timeout=60)  # 60-second cap
    if not out: bullet("whois", f"no data returned ({err or 'empty response'})"); return
    printed = set()                                   # de-duplicate keys
    for line in out.splitlines():                     # iterate registry lines
        if ":" not in line: continue                  # skip separators
        k, v = line.split(":", 1)                     # split on first colon
        k = k.strip().lower(); v = v.strip()          # normalise
        if k in WHOIS_KEYS and v and k not in printed:
            printed.add(k); bullet(k.title(), v[:140])
    if not printed: bullet("whois", "no recognised registry fields in the response")


# =============================================================================
#  [6] SUBFINDER  —  passive subdomain enumeration
# =============================================================================

def module_subfinder(target):
    # Enumerate subdomains with subfinder. Returns the discovered list.
    section(6, "subfinder passive subdomain enumeration")
    if not looks_like_domain(target):                 # not a domain?
        bullet("Subfinder", "skipped - target is not a DNS domain name")
        return []
    if not shutil.which("subfinder"):                 # installed?
        bullet("subfinder", "NOT INSTALLED - see github.com/projectdiscovery/subfinder")
        return []
    cmd = ["subfinder", "-d", target, "-silent", "-all"]
    bullet("Command", " ".join(cmd))                  # print the command
    out, err, rc = run(cmd, timeout=600)              # 10-minute cap
    if not out:                                       # nothing returned
        bullet("Subdomains found", "0")
        if err: sub(err.splitlines()[0])              # show first error line
        return []
    subs = []                                         # accumulator
    seen = set()                                      # de-dup set
    for line in out.splitlines():                     # iterate tool output
        n = line.strip().lower()                      # normalise the line
        if not n or n in seen: continue               # skip blank/duplicate
        seen.add(n); subs.append(n)                   # remember + keep
    bullet("Subdomains found", str(len(subs)))        # report count
    for n in subs: sub(n)                             # nested bullet each
    if len(subs) > 20:                                # large attack surface?
        FINDINGS.append(("INFO", f"large subdomain attack surface ({len(subs)} hosts)"))
    return subs


# =============================================================================
#  [7] NMAP  —  guided questions, auto-built arguments, pretty XML output
# =============================================================================

PORT_RISK = {                                         # static port -> risk map
    "21":    ("HIGH",     "FTP - credentials and data cross the wire in cleartext"),
    "23":    ("HIGH",     "Telnet - cleartext remote shell"),
    "25":    ("MEDIUM",   "SMTP - open relay / user enumeration risk"),
    "111":   ("MEDIUM",   "rpcbind - RPC service enumeration"),
    "139":   ("HIGH",     "NetBIOS - legacy SMB exposure"),
    "445":   ("CRITICAL", "SMB - lateral movement / EternalBlue class bugs"),
    "512":   ("HIGH",     "rexec - legacy remote execution, no encryption"),
    "513":   ("HIGH",     "rlogin - legacy remote login, no encryption"),
    "514":   ("HIGH",     "rsh - legacy remote shell, no encryption"),
    "1099":  ("HIGH",     "Java RMI - deserialization remote code execution"),
    "1524":  ("CRITICAL", "bindshell - pre-installed root shell backdoor"),
    "2049":  ("HIGH",     "NFS - often exported without authentication"),
    "3306":  ("HIGH",     "MySQL - database exposed to the network"),
    "5432":  ("HIGH",     "PostgreSQL - database exposed to the network"),
    "5900":  ("HIGH",     "VNC - remote desktop, weak auth schemes"),
    "6000":  ("MEDIUM",   "X11 - display server exposure"),
    "6667":  ("CRITICAL", "IRC - UnrealIRCd 3.2.8.1 shipped a trojan backdoor"),
    "8009":  ("MEDIUM",   "AJP13 - Tomcat connector, ghostcat class bugs"),
    "8180":  ("HIGH",     "Tomcat - old manager interface, deploy WARs"),
}

VERSION_RISK = [                                      # version fingerprint rules
    (re.compile(r"vsftpd 2\.3\.4", re.I), "CRITICAL",
     "vsftpd 2.3.4 - smiley backdoor on port 6200 (CVE-2011-2523)"),
    (re.compile(r"Unreal3?2?\.?8\.?1|UnrealIRCd", re.I), "CRITICAL",
     "UnrealIRCd 3.2.8.1 - trojaned source tree backdoor"),
    (re.compile(r"Samba 3\.0\.20", re.I), "CRITICAL",
     "Samba 3.0.20 - username map script RCE (CVE-2007-2447)"),
    (re.compile(r"ProFTPD 1\.3\.1", re.I), "HIGH",
     "ProFTPD 1.3.1 - multiple remote code execution flaws"),
    (re.compile(r"Apache Tomcat/5\.5", re.I), "HIGH",
     "Tomcat 5.5 - end-of-life, multiple RCE and manager flaws"),
    (re.compile(r"OpenSSH 4\.7", re.I), "MEDIUM",
     "OpenSSH 4.7p1 - legacy build, weak default configuration"),
    (re.compile(r"MySQL 5\.0", re.I), "MEDIUM",
     "MySQL 5.0.x - end-of-life, root-with-no-password default"),
    (re.compile(r"PostgreSQL 8\.3", re.I), "MEDIUM",
     "PostgreSQL 8.3 - end-of-life, no longer patched"),
    (re.compile(r"Apache/2\.2\.8", re.I), "MEDIUM",
     "Apache 2.2.8 - end-of-life branch, unpatched since 2017"),
    (re.compile(r"ISC BIND 9\.4\.2", re.I), "MEDIUM",
     "BIND 9.4.2 - end-of-life, cache-poisoning era build"),
]


def nmap_options():
    # Ask every nmap question in one pass and return the answer dictionary.
    print(f"\n{B}{I}nmap - answer simply, the flags are built for you{R}")

    # -------- Q1: TCP/UDP scan technique (-sS, -sT, -sA, ...) ------------
    print(f"{B}{I}Scan technique:{R}")                # menu header
    for k in sorted(SCAN_TYPES.keys()):               # iterate menu entries
        flag, desc = SCAN_TYPES[k]                    # unpack flag + description
        print(f"    [{k}] {B}{I}{flag}{R}  {desc}")   # print one menu line
    t = ask("Choose scan technique [1-8, default 1]:", "1")   # read choice
    if t not in SCAN_TYPES:                           # invalid choice?
        bullet("Note", f"invalid choice '{t}' - defaulting to -sS")   # note
        t = "1"                                       # force default
    scan_flag = SCAN_TYPES[t][0]                      # extract the flag string
    scan_desc = SCAN_TYPES[t][1]                      # extract the description

    # Warn the operator if -sS is chosen without root privileges.
    if scan_flag == "-sS" and os.geteuid() != 0:      # SYN scan needs root
        bullet("Note", "-sS requires root - falling back to -sT")   # note
        scan_flag = "-sT"                             # force TCP connect
        scan_desc = SCAN_TYPES["2"][1]                # update description

    o = {}                                            # answer holder
    o["scan"] = scan_flag                             # remember chosen flag
    o["scan_desc"] = scan_desc                        # remember description
    o["sV"] = ask("Version + service detection (-sV)? [Y/n]", "y").lower().startswith("y")
    o["sC"] = ask("Default NSE scripts (-sC)? [y/N]", "n").lower().startswith("y")
    o["scope"] = ask("Ports: [1] top-1000  [2] all 65535 (-p-)  [3] custom (-p)  [1]", "1")
    o["custom"] = ""                                  # default custom list
    if o["scope"] == "3":                             # custom chosen?
        o["custom"] = ask("Custom ports (e.g. 22,80,443 or 1-1024):", "")
    o["Pn"] = ask("Skip host discovery (-Pn)? [Y/n]", "y").lower().startswith("y")
    tm = ask("Timing (-T1 to -T5)? [1-5, default 4]:", "4")
    o["T"] = tm if tm in ("1", "2", "3", "4", "5") else "4"
    return o


def build_nmap_args(o):
    # Convert the answer dictionary into an ordered nmap argument list.
    a = [o["scan"]]                                   # always the scan flag first
    if o["sV"]: a.append("-sV")                       # version detection
    if o["sC"]: a.append("-sC")                       # default scripts
    if o["scope"] == "2": a += ["-p-"]                # all 65535 ports
    elif o["scope"] == "3" and o["custom"]: a += ["-p", o["custom"]]
    if o["Pn"]: a.append("-Pn")                       # skip host discovery
    a.append(f"-T{o['T']}")                           # timing template
    return a


def nmap_module(target, args, scan_desc=""):
    # Run nmap, parse its XML and print a clean, bullet-point port map.
    section(7, "nmap port & service map")
    if not shutil.which("nmap"):                      # nmap is mandatory
        bullet("nmap", "NOT INSTALLED - run: sudo apt install nmap"); return
    if os.geteuid() != 0:                             # privilege note only
        bullet("Note", "not root - SYN scan and OS detection unavailable")
    if scan_desc:                                     # show the chosen technique
        bullet("Scan technique", scan_desc)
    cmd = ["nmap"] + args + ["-oX", "-", target]      # -oX - streams XML
    bullet("Command", " ".join(cmd))                  # print the command
    raw, err, rc = run(cmd, timeout=3600)             # 1-hour cap
    if not raw.lstrip().startswith("<?xml"):          # no XML returned?
        bullet("nmap", "no XML output - target unreachable or blocked")
        if err: sub(err.splitlines()[0])
        return
    try:                                              # XML may be malformed
        root = ET.fromstring(raw)                     # parse the document
    except ET.ParseError:
        bullet("nmap", "XML parse failure"); return
    finished = root.find("runstats/finished")         # timing block
    hosts = root.findall("host")                      # every host element
    up = [h for h in hosts                            # filter live hosts
          if h.find("status") is not None and h.find("status").get("state") == "up"]
    bullet("Hosts scanned", str(len(hosts)))          # count scanned
    bullet("Hosts up", str(len(up)))                  # count live
    if finished is not None:
        bullet("Scan duration", f"{finished.get('elapsed', '?')}s")
    for host in up:                                   # loop each live host
        ip = None; mac = None                         # reset per host
        for a in host.findall("address"):             # iterate addresses
            if a.get("addrtype") in ("ipv4", "ipv6"): # IP address?
                ip = a.get("addr")                    # network address
            elif a.get("addrtype") == "mac":          # MAC address?
                mac = f"{a.get('addr')} ({a.get('vendor', 'unknown')})"
        names = [n.get("name") for n in host.findall("hostnames/hostname")]
        times = host.find("times"); srtt = "n/a"      # timing element, default
        if times is not None and times.get("srtt"):   # srtt present?
            srtt = f"{int(times.get('srtt')) / 1000:.4f}s"
        bullet("Host", f"{ip}  ({names[0] if names else 'no PTR'})")
        bullet("Latency", srtt)                       # latency bullet
        if mac: bullet("MAC", mac)                    # MAC bullet if present
        for osm in host.findall("os/osmatch"):        # iterate OS matches
            acc = osm.get("accuracy", "?")            # accuracy percentage
            bullet("OS guess", f"{osm.get('name')}  ({acc}% confidence)")
            break                                     # best match only
        ports = host.findall("ports/port")            # every port element
        open_ports = [p for p in ports                # filter open ports
                      if p.find("state") is not None
                      and p.find("state").get("state") == "open"]
        bullet("Open TCP ports", f"{len(open_ports)} of {len(ports)} scanned")
        for p in open_ports:                          # iterate each open port
            portid = p.get("portid")                  # e.g. "21"
            proto = p.get("protocol")                 # "tcp"
            svc = p.find("service")                   # <service .../>
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            extrainfo = svc.get("extrainfo", "") if svc is not None else ""
            banner_txt = " ".join(x for x in (product, version, extrainfo) if x)
            tail = ("  -  " + banner_txt) if banner_txt else ""
            print(f"    - {B}{I}{portid}/{proto}{R}  open  {name}{tail}")
            if portid in PORT_RISK:                   # known risky port?
                sev, msg = PORT_RISK[portid]
                sub(f"{B}{I}[{sev}]{R} {style_split(msg)}")
                FINDINGS.append((sev, f"{portid}/{proto} - {msg}"))
            hay = f"{name} {banner_txt}"              # combined text to search
            for rx, sev, msg in VERSION_RISK:         # iterate fingerprint rules
                if rx.search(hay):
                    sub(f"{B}{I}[{sev}]{R} {style_split(msg)}")
                    FINDINGS.append((sev, msg))
            for script in p.findall("script"):        # iterate script elements
                lines = [l for l in script.get("output", "").splitlines() if l.strip()]
                if not lines: continue
                sub(f"NSE {script.get('id')}: {lines[0][:100]}")
                for extra in lines[1:6]: sub(extra[:100])
                if script.get("id") == "ftp-anon" and "anonymous" in lines[0].lower():
                    FINDINGS.append(("HIGH", "Anonymous FTP login permitted"))
        for script in host.findall("hostscript/script"):   # host-level scripts
            lines = [l for l in script.get("output", "").splitlines() if l.strip()]
            if not lines: continue
            sub(f"Host script {script.get('id')}: {lines[0][:100]}")
            for extra in lines[1:4]: sub(extra[:100])


# =============================================================================
#  [8] EXECUTIVE SUMMARY
# =============================================================================

def module_summary(target, report_path):
    # Condense every finding into a severity-ranked closing block.
    section(8, "executive summary")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    counts = {}                                       # severity tally
    for sev, _ in FINDINGS:
        counts[sev] = counts.get(sev, 0) + 1
    bullet("Target", target)                          # print target
    bullet("Total findings", str(len(FINDINGS)))      # total count
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        if counts.get(sev):
            bullet(f"{sev} findings", str(counts[sev]))
    if counts.get("CRITICAL"):
        v = "CRITICAL - remotely exploitable services are exposed"
    elif counts.get("HIGH"):
        v = "HIGH - multiple high-impact exposures present"
    elif counts.get("MEDIUM"):
        v = "MEDIUM - hardening gaps, no trivially exploitable service"
    else:
        v = "LOW - no significant exposure detected"
    bullet("Verdict", v)                              # one-line verdict
    print()                                           # blank line
    seen = set()                                      # de-dup set
    for sev, msg in sorted(FINDINGS, key=lambda f: order.get(f[0], 9)):
        if msg in seen: continue                      # skip duplicates
        seen.add(msg)
        print(f"- {B}{I}[{sev}]{R} {style_split(msg)}")
    print()                                           # blank line
    if report_path:
        bullet("Report saved", report_path)
    else:
        bullet("Report", "not saved (console only)")


# =============================================================================
#  MAIN
# =============================================================================

def main():
    # Wire every module together into one sequential recon workflow.
    banner()                                          # print identity block
    for tool in ("curl", "nmap"):                     # hard requirements
        if not shutil.which(tool):
            print(f"{B}{I}[!] missing required tool: {tool}{R}"); sys.exit(1)
    target = ask("Target (IP or domain):", "")        # collect the target
    if not target:
        print(f"{B}{I}[!] no target supplied - aborting{R}"); sys.exit(1)
    save = ask("Save report to file? [Y/n]", "y").lower().startswith("y")
    opts = nmap_options()                             # ask every nmap question
    nmap_args = build_nmap_args(opts)                 # auto-build flag list
    report_path = None; tee = None                    # defaults
    if save:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
        report_path = f"subfinder_{safe}_{datetime.now():%Y%m%d_%H%M%S}.txt"
        tee = Tee(report_path); sys.stdout = tee
        print(f"{B}{I}Writing report to {report_path}{R}")
    else:
        print(f"{B}{I}Saving disabled - output goes to console only{R}")
    module_public_ip()                                # [1] curl egress IP
    module_ifconfig()                                 # [2] local interfaces
    module_http(target)                               # [3] HTTP audit
    module_whatweb(target)                            # [4] web fingerprint
    module_whois(target)                              # [5] registry lookup
    module_subfinder(target)                          # [6] subfinder
    nmap_module(target, nmap_args, opts["scan_desc"]) # [7] nmap LAST
    module_summary(target, report_path)               # [8] exec summary
    if tee is not None:
        sys.stdout = sys.__stdout__                   # restore stdout
        tee.close()                                   # close report file
    print(f"\n{B}{I}Recon workflow finished.{R}")


# Standard Python entry-point guard.
if __name__ == "__main__":
    main()
