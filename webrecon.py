#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  S U B F I N D E R  ·  merged reconnaissance engine   (Kali Linux / Python 3)
# -----------------------------------------------------------------------------
#  Module order   : curl (public IP)  ->  ifconfig  ->  subfinder
#                   curl (HTTP audit) ->  whatweb   ->  whois  ->  nmap
#                   ->  executive summary
#  Style rule     : NO colour. Everything before the first ':' or '—' is
#                   rendered BOLD + ITALIC. Everything after is plain.
#  Run as         : sudo python3 webrecon.py
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

FINDINGS = []   # list of (severity, message) tuples


# =============================================================================
#  STYLE HELPERS
# =============================================================================

def style_split(text):
    """Bold+italic everything before the first ':' or '—', leave the rest plain."""
    colon = text.find(":")                        # index of first colon, -1 if none
    dash = text.find("—")                         # index of first em-dash, -1 if none
    cuts = [c for c in (colon, dash) if c != -1]  # keep only the ones that exist
    if not cuts:                                  # no separator found
        return text                               # return the text untouched
    cut = min(cuts)                               # earliest separator wins
    prefix = text[:cut].rstrip()                  # left side, trimmed
    rest = text[cut:]                             # separator + right side, verbatim
    return f"{B}{I}{prefix}{R}{rest}"             # styled prefix + plain tail


# =============================================================================
#  OUTPUT PLUMBING
# =============================================================================

class Tee:
    """Mirror everything printed to the terminal into a plain-text report."""

    def __init__(self, path):                     # constructor takes file path
        self.fh = open(path, "w", encoding="utf-8")   # write handle for report

    def write(self, data):                        # called by print() implicitly
        sys.__stdout__.write(data)                # bypass our own redirect
        self.fh.write(ANSI_RE.sub("", data))      # strip escapes then write

    def flush(self):                              # called by print() implicitly
        sys.__stdout__.flush()                    # flush terminal buffer
        self.fh.flush()                           # flush file buffer

    def close(self):                              # manual cleanup at the end
        self.fh.close()                           # close report file


def banner():
    """One-time identity block. No fluff, just the engine name."""
    print(f"{B}{I}")                              # switch on bold + italic
    print("  ╔══════════════════════════════════════════════════════════════════╗")  # top border
    print("  ║   S U B F I N D E R   ·   RECON INTELLIGENCE ENGINE               ║")  # title line
    print("  ║   curl · ifconfig · subfinder · whatweb · whois · nmap            ║")  # tools line
    print("  ╚══════════════════════════════════════════════════════════════════╝")  # bottom border
    print(f"{R}")                                 # reset styling


def section(idx, title):
    """Print a numbered section divider."""
    bar = "━" * 70                                # heavy horizontal rule
    print(f"\n{B}{bar}{R}")                       # print rule in bold
    print(f"{B}{I}  [{idx}]  {title.upper()}{R}") # print numbered title
    print(f"{B}{bar}{R}")                         # print rule again in bold


def bullet(label, value=""):
    """Top-level bullet. The label (or the prefix of the label) is styled."""
    if value == "":                               # no value supplied?
        print(f"- {style_split(label)}")          # label-only bullet
    else:                                         # value supplied?
        print(f"- {B}{I}{label}{R}: {value}")     # label + value bullet


def sub(text):
    """Nested bullet. Prefix before ':' or '—' is styled, tail stays plain."""
    print(f"    - {style_split(text)}")          # four-space indent + dash


def ask(prompt, default=""):
    """Ask one simple question and return the answer, or the default."""
    try:                                          # input() can raise on EOF
        ans = input(f"{B}{I}{prompt}{R} ").strip()# show prompt and read answer
    except EOFError:                              # non-interactive stdin
        ans = ""                                  # treat as empty answer
    return ans if ans else default                # fall back to default


def run(cmd, timeout=600):
    """Run a command list, capture stdout/stderr, never raise. (out, err, rc)"""
    try:                                          # catch expected failures
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # execute
        return p.stdout.strip(), p.stderr.strip(), p.returncode   # return triple
    except FileNotFoundError:                     # binary not installed
        return "", f"{cmd[0]}: not installed", 127   # shell-style rc 127
    except subprocess.TimeoutExpired:             # command ran too long
        return "", f"{cmd[0]}: timed out", 124    # shell-style rc 124


def is_private_ip(value):
    """True when the string is an RFC1918 / loopback / link-local address."""
    try:                                          # ipaddress raises on bad input
        return ipaddress.ip_address(value).is_private   # returns True/False
    except ValueError:                            # not an IP at all (domain)
        return False                              # treat domains as public


def looks_like_domain(value):
    """True when the string looks like a DNS name (has a dot, not an IP)."""
    if is_private_ip(value):                      # private IP -> not a domain
        return False                              # bail out
    try:                                          # try to parse as IP
        ipaddress.ip_address(value)               # succeeds -> it's a raw IP
        return False                              # raw IP is not a domain
    except ValueError:                            # not an IP -> likely a domain
        return "." in value                       # domains need at least one dot


# =============================================================================
#  [1] PUBLIC IP  —  curl only
# =============================================================================

def module_public_ip():
    """Discover the egress public IP and its registration identity via curl."""
    section(1, "public ip / egress identity")     # print the section header

    ip = None                                     # holds the discovered IP
    for url in ("https://ifconfig.me/ip",         # endpoint #1
                "https://api.ipify.org",          # endpoint #2
                "https://ipinfo.io/ip"):          # endpoint #3
        out, err, rc = run(["curl", "-s", "--max-time", "10", url])  # query it
        if rc == 0 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", out or ""):  # validate
            ip = out                              # remember the IP
            bullet("Public IP", ip)               # print the IP
            bullet("Resolved via", url)           # print which endpoint answered
            break                                 # stop at first success

    if not ip:                                    # every endpoint failed
        bullet("Public IP", "unavailable (no egress / curl blocked)")  # report
        return                                    # nothing more to do

    STATE["public_ip"] = ip                       # cache for the whois module

    out, err, rc = run(["curl", "-s", "--max-time", "10",      # curl call
                        f"https://ipinfo.io/{ip}/json"])       # JSON endpoint
    if rc == 0 and out:                           # only parse on success
        try:                                      # JSON may be malformed
            data = json.loads(out)                # parse the JSON blob
            for key in ("hostname", "city", "region", "country",   # useful keys
                        "loc", "org", "timezone"):                 # more keys
                if data.get(key):                 # only if key present & truthy
                    bullet(key.capitalize(), data[key])   # print bullet
        except json.JSONDecodeError:              # malformed JSON
            bullet("Geo/ASN enrichment", "unavailable")   # report failure


# =============================================================================
#  [2] IFCONFIG  —  local interfaces, parsed, zero fluff
# =============================================================================

def parse_ifconfig(text):
    """Turn raw `ifconfig -a` output into a list of interface dictionaries."""
    ifaces = []                                   # accumulator
    cur = None                                    # interface being filled
    for line in text.splitlines():                # iterate every output line
        if not line.strip():                      # blank line
            continue                              # skip blank separators
        if not line[0].isspace():                 # header line = new iface
            m = re.match(r"^(\S+?):\s+flags=\d+<([^>]*)>(?:\s+mtu\s+(\d+))?", line)  # capture
            if m:                                 # header matched
                cur = {"name": m.group(1),        # e.g. eth0
                       "flags": m.group(2).split(","),   # UP,RUNNING,...
                       "mtu": m.group(3) or "?",  # MTU value
                       "inet": [], "inet6": [], "mac": None}   # empty holders
                ifaces.append(cur)                # register this interface
            else:                                 # unrecognised header
                cur = None                        # stop filling previous iface
        elif cur is not None:                     # detail line
            s = line.strip()                      # trim whitespace
            m = re.match(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", s)  # IPv4?
            if m:                                 # IPv4 matched
                cur["inet"].append(m.group(1))    # IPv4 address
                continue                          # next line
            m = re.match(r"inet6 (?:addr: )?([0-9a-fA-F:]+)", s)     # IPv6?
            if m:                                 # IPv6 matched
                cur["inet6"].append(m.group(1))   # IPv6 address
                continue                          # next line
            m = re.match(r"ether ([0-9a-fA-F:]{17})", s)             # MAC?
            if m:                                 # MAC matched
                cur["mac"] = m.group(1)           # hardware address
    return ifaces                                 # hand back the parsed list


def module_ifconfig():
    """Dump every local interface as a tight bullet list, no noise."""
    section(2, "local interfaces (ifconfig, no fluff)")   # section header

    if shutil.which("ifconfig"):                  # preferred (user request)
        raw, err, rc = run(["ifconfig", "-a"])    # ask for all interfaces
    else:                                         # modern fallback
        raw, err, rc = run(["ip", "-o", "addr"])  # use iproute2 instead
        bullet("Note", "ifconfig missing — used `ip -o addr` instead")  # note

    if not raw:                                   # nothing captured
        bullet("Interfaces", "no output (run with sufficient privileges)")  # warn
        return                                    # stop this module

    for iface in parse_ifconfig(raw):             # loop each parsed interface
        state = "UP" if "UP" in iface["flags"] else "DOWN"   # up/down state
        bullet(f"Interface {iface['name']} [{state}]",        # top-level bullet
               ", ".join(f for f in iface["flags"] if f != "UP"))  # flag list
        for addr in iface["inet"]:                # each IPv4 address
            sub(f"IPv4: {addr}")                  # nested bullet
        for addr in iface["inet6"]:               # each IPv6 address
            sub(f"IPv6: {addr}")                  # nested bullet
        if iface["mac"]:                          # MAC present?
            sub(f"MAC: {iface['mac']}")           # nested bullet
        sub(f"MTU: {iface['mtu']}")               # always show MTU


# =============================================================================
#  [3] SUBFINDER  —  passive subdomain enumeration
# =============================================================================

def module_subfinder(target):
    """Enumerate subdomains with subfinder. Returns the discovered list."""
    section(3, "subfinder passive subdomain enumeration")   # section header

    if not looks_like_domain(target):                         # not a domain?
        bullet("Subfinder", "skipped — target is not a DNS domain name")  # note
        return []                                             # empty list

    if not shutil.which("subfinder"):                         # is it installed?
        bullet("subfinder", "NOT INSTALLED — see https://github.com/projectdiscovery/subfinder")  # warn
        return []                                             # empty list

    # -d <domain>  : the apex domain to enumerate
    # -silent      : print only the hostnames, no banner / stats / colours
    # -all         : use every passive source available (slower, more complete)
    cmd = ["subfinder", "-d", target, "-silent", "-all"]      # build the command
    bullet("Command", " ".join(cmd))                          # print the command

    out, err, rc = run(cmd, timeout=600)                      # allow 10 minutes
    if not out:                                               # nothing returned
        bullet("Subdomains found", "0")                       # report zero
        if err:                                               # any stderr?
            sub(err.splitlines()[0])                          # show first line
        return []                                             # empty list

    subs = []                                                 # accumulator
    seen = set()                                              # de-dup set
    for line in out.splitlines():                             # iterate output
        name = line.strip().lower()                           # normalise
        if not name or name in seen:                          # blank or dupe?
            continue                                          # skip
        seen.add(name)                                        # remember it
        subs.append(name)                                     # keep it

    bullet("Subdomains found", str(len(subs)))                # report count
    for name in subs:                                         # iterate each one
        sub(name)                                             # nested bullet

    if len(subs) > 20:                                        # large attack surface?
        FINDINGS.append(("INFO", f"large subdomain attack surface ({len(subs)} hosts)"))  # record

    return subs                                               # hand back the list


# =============================================================================
#  [4] CURL HTTP HEADER AUDIT
# =============================================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": "forces HTTPS on all future requests",  # HSTS
    "Content-Security-Policy": "blocks XSS / injection payload delivery", # CSP
    "X-Frame-Options": "blocks clickjacking via iframes",                # framing
    "X-Content-Type-Options": "blocks MIME-type sniffing",               # sniffing
    "Referrer-Policy": "controls referrer leakage to third parties",     # referrer
    "Permissions-Policy": "locks down browser feature access",           # features
    "X-XSS-Protection": "legacy reflected-XSS filter",                   # legacy XSS
    "Cross-Origin-Opener-Policy": "isolates the browsing context",       # COOP
    "Cross-Origin-Resource-Policy": "blocks cross-origin resource reads",# CORP
    "Cross-Origin-Embedder-Policy": "blocks cross-origin embedding",     # COEP
}


def parse_header_blocks(raw):
    """Split a `curl -D -` dump into [(status_line, {header: value}), ...]."""
    blocks = []                                   # accumulator
    for chunk in re.split(r"\r?\n\r?\n+", raw.strip()):   # split on blank lines
        lines = [l for l in chunk.splitlines() if l.strip()]   # drop empties
        if not lines or not lines[0].upper().startswith("HTTP/"):  # not a header
            continue                              # skip non-header chunks
        status = lines[0].strip()                 # first line is the status
        headers = {}                              # header dictionary
        for line in lines[1:]:                    # remaining lines
            if ":" in line:                       # valid header line?
                k, v = line.split(":", 1)         # split on first colon only
                headers[k.strip()] = v.strip()    # store key -> value
        blocks.append((status, headers))          # add this block
    return blocks                                 # return all blocks


def probe_url(url):
    """Fetch headers with curl and report status, redirects and header audit."""
    raw, err, rc = run(["curl", "-s", "-k", "-L", "-o", "/dev/null", "-D", "-",   # args
                        "--max-time", "15", "-A", UA, url])                       # target
    if rc != 0 or not raw:                        # curl failed or empty
        bullet(f"URL {url}", "unreachable")       # report unreachable
        return False                              # signal failure

    blocks = parse_header_blocks(raw)             # every hop of the chain
    if not blocks:                                # no parseable headers
        bullet(f"URL {url}", "no HTTP response")  # report
        return False                              # signal failure

    status, headers = blocks[-1]                  # final response wins
    lower = {k.lower(): v for k, v in headers.items()}   # case-insensitive map

    bullet("URL", url)                            # print the URL
    bullet("Final status", status)                # print final status line
    bullet("Redirect hops", str(max(0, len(blocks) - 1)))   # count redirects

    body, _, _ = run(["curl", "-s", "-k", "-L", "--max-time", "15", "-A", UA, url])  # body
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)   # find title
    if m:                                         # title matched
        bullet("Page title", re.sub(r"\s+", " ", m.group(1)).strip()[:90]) # collapse

    if headers:                                   # any headers at all?
        bullet("Headers returned", str(len(headers)))   # count
        for k, v in headers.items():              # iterate each header
            sub(f"{k}: {v[:120]}")                # styled key, plain value

    present = [h for h in SECURITY_HEADERS if h.lower() in lower]   # included
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower] # missing

    bullet("Security headers INCLUDED", f"{len(present)}/{len(SECURITY_HEADERS)}")  # count
    for h in present:                             # each included header
        sub(f"{h}: {lower[h.lower()]}  —  {SECURITY_HEADERS[h]}")   # styled key

    bullet("Security headers MISSING", f"{len(missing)}/{len(SECURITY_HEADERS)}")   # count
    for h in missing:                             # each missing header
        sub(f"{h}: {SECURITY_HEADERS[h]}")        # styled key, plain note

    if missing:                                   # any missing headers?
        FINDINGS.append(("MEDIUM",                # record a finding
                         f"{len(missing)} security headers absent on {url}"))

    return True                                   # signal success


def module_http(target):
    """Run the curl HTTP header audit across http:// and https://."""
    section(4, "curl http header audit")          # section header

    if not shutil.which("curl"):                  # curl is mandatory here
        bullet("curl", "NOT INSTALLED — run: sudo apt install curl")   # warn
        return                                    # stop module

    host = re.sub(r"^https?://", "", target).split("/")[0]   # strip any scheme

    for scheme in ("http", "https"):              # try both schemes
        url = f"{scheme}://{host}/"               # build the URL
        probe_url(url)                            # audit it (no path bruteforce)


# =============================================================================
#  [5] WHATWEB
# =============================================================================

def module_whatweb(target):
    """Fingerprint web technologies with whatweb, printed as clean bullets."""
    section(5, "whatweb technology fingerprint")  # section header

    if not shutil.which("whatweb"):               # optional dependency
        bullet("whatweb", "NOT INSTALLED — run: sudo apt install whatweb")   # warn
        return                                    # stop module

    cmd = ["whatweb", "-a", "3", "--color=never", "--no-errors",   # aggressive, no colour
           f"http://{target}/"]                   # target URL
    out, err, rc = run(cmd, timeout=180)          # run with a 3-minute cap
    if not out:                                   # no output at all
        bullet("whatweb", "no fingerprint returned")   # warn
        return                                    # stop module

    seen = set()                                  # de-duplication set
    for name, value in re.findall(r"([A-Za-z][A-Za-z0-9_\-]*)\[([^\[\]]*)\]", out):  # parse
        pair = (name, value)                      # tuple for the set
        if pair in seen:                          # already printed?
            continue                              # skip duplicates
        seen.add(pair)                            # remember it
        bullet(name, value)                       # styled name, plain value

    if not seen:                                  # nothing matched
        bullet("whatweb", "no plugins matched")   # warn


# =============================================================================
#  [6] WHOIS
# =============================================================================

WHOIS_KEYS = {
    "domain name", "registrar", "registrar url", "creation date", "updated date",
    "expiry date", "registry expiry date", "name server", "dnssec", "status",
    "registrant organization", "registrant country",
    "netrange", "cidr", "netname", "orgname", "organization", "orgid",
    "country", "regdate", "updated", "abuseemail", "orgabuseemail",
    "orgabusename", "descr", "inetnum", "route", "origin", "mnt-by",
    "referral server", "address", "e-mail",
}


def module_whois(target):
    """Query the registry for the target, or fall back to the egress IP."""
    section(6, "whois registry lookup")           # section header

    if not shutil.which("whois"):                 # optional dependency
        bullet("whois", "NOT INSTALLED — run: sudo apt install whois")   # warn
        return                                    # stop module

    query = target                                # what we actually query
    if is_private_ip(target):                     # RFC1918 has no registry
        bullet("Note", "target is a private RFC1918 address — no registry entry")  # note
        if STATE["public_ip"]:                    # we have an egress IP cached?
            query = STATE["public_ip"]            # fall back to egress IP
            bullet("Fallback query", query)       # announce the fallback
        else:                                     # no fallback available
            bullet("whois", "skipped — no public IP available")   # warn
            return                                # stop module

    out, err, rc = run(["whois", query], timeout=60)   # query the registry
    if not out:                                   # nothing returned
        bullet("whois", f"no data returned ({err or 'empty response'})")   # warn
        return                                    # stop module

    printed = set()                               # de-duplicate keys
    for line in out.splitlines():                 # iterate registry lines
        if ":" not in line:                       # skip separators / comments
            continue                              # next line
        key, value = line.split(":", 1)           # split on first colon only
        key = key.strip().lower()                 # normalise for lookup
        value = value.strip()                     # trim value
        if key in WHOIS_KEYS and value and key not in printed:   # keep only useful
            printed.add(key)                      # remember we printed it
            bullet(key.title(), value[:140])      # styled key, plain value

    if not printed:                               # nothing useful found
        bullet("whois", "no recognised registry fields in the response")   # warn


# =============================================================================
#  [7] NMAP  —  guided questions, auto-built arguments, pretty XML output
# =============================================================================

PORT_RISK = {
    "21":    ("HIGH",     "FTP — credentials and data cross the wire in cleartext"),  # FTP
    "23":    ("HIGH",     "Telnet — cleartext remote shell"),                         # Telnet
    "25":    ("MEDIUM",   "SMTP — open relay / user enumeration risk"),               # SMTP
    "111":   ("MEDIUM",   "rpcbind — RPC service enumeration"),                       # rpcbind
    "139":   ("HIGH",     "NetBIOS — legacy SMB exposure"),                           # NetBIOS
    "445":   ("CRITICAL", "SMB — lateral movement / EternalBlue class bugs"),         # SMB
    "512":   ("HIGH",     "rexec — legacy remote execution, no encryption"),          # rexec
    "513":   ("HIGH",     "rlogin — legacy remote login, no encryption"),             # rlogin
    "514":   ("HIGH",     "rsh — legacy remote shell, no encryption"),                # rsh
    "1099":  ("HIGH",     "Java RMI — deserialization remote code execution"),        # RMI
    "1524":  ("CRITICAL", "bindshell — pre-installed root shell backdoor"),           # shell
    "2049":  ("HIGH",     "NFS — often exported without authentication"),             # NFS
    "3306":  ("HIGH",     "MySQL — database exposed to the network"),                 # MySQL
    "5432":  ("HIGH",     "PostgreSQL — database exposed to the network"),            # PgSQL
    "5900":  ("HIGH",     "VNC — remote desktop, weak auth schemes"),                 # VNC
    "6000":  ("MEDIUM",   "X11 — display server exposure"),                           # X11
    "6667":  ("CRITICAL", "IRC — UnrealIRCd 3.2.8.1 shipped a trojan backdoor"),      # IRC
    "8009":  ("MEDIUM",   "AJP13 — Tomcat connector, ghostcat class bugs"),           # AJP
    "8180":  ("HIGH",     "Tomcat — old manager interface, deploy WARs"),             # Tomcat
}

VERSION_RISK = [
    (re.compile(r"vsftpd 2\.3\.4", re.I),                                     # pattern
     "CRITICAL", "vsftpd 2.3.4 — smiley backdoor on port 6200 (CVE-2011-2523)"),  # note
    (re.compile(r"Unreal3?2?\.?8\.?1|UnrealIRCd", re.I),                      # pattern
     "CRITICAL", "UnrealIRCd 3.2.8.1 — trojaned source tree backdoor"),       # note
    (re.compile(r"Samba 3\.0\.20", re.I),                                     # pattern
     "CRITICAL", "Samba 3.0.20 — username map script RCE (CVE-2007-2447)"),   # note
    (re.compile(r"ProFTPD 1\.3\.1", re.I),                                    # pattern
     "HIGH", "ProFTPD 1.3.1 — multiple remote code execution flaws"),         # note
    (re.compile(r"Apache Tomcat/5\.5", re.I),                                 # pattern
     "HIGH", "Tomcat 5.5 — end-of-life, multiple RCE and manager flaws"),     # note
    (re.compile(r"OpenSSH 4\.7", re.I),                                       # pattern
     "MEDIUM", "OpenSSH 4.7p1 — legacy build, weak default configuration"),   # note
    (re.compile(r"MySQL 5\.0", re.I),                                         # pattern
     "MEDIUM", "MySQL 5.0.x — end-of-life, root-with-no-password default"),   # note
    (re.compile(r"PostgreSQL 8\.3", re.I),                                    # pattern
     "MEDIUM", "PostgreSQL 8.3 — end-of-life, no longer patched"),            # note
    (re.compile(r"Apache/2\.2\.8", re.I),                                     # pattern
     "MEDIUM", "Apache 2.2.8 — end-of-life branch, unpatched since 2017"),    # note
    (re.compile(r"ISC BIND 9\.4\.2", re.I),                                   # pattern
     "MEDIUM", "BIND 9.4.2 — end-of-life, cache-poisoning era build"),        # note
]


def nmap_options():
    """Ask five simple questions and translate the answers into nmap flags."""
    print(f"\n{B}{I}nmap — answer simply, the flags are built for you{R}")  # intro
    opts = {}                                     # holds all answers
    opts["sV"] = ask("Version + service detection (-sV)? [Y/n]", "y").lower().startswith("y")  # Q1
    opts["sC"] = ask("Default NSE scripts (-sC)? [y/N]", "n").lower().startswith("y")          # Q2
    opts["scope"] = ask("Ports: [1] top-1000  [2] all 65535 (-p-)  [3] custom (-p)  [1]", "1")  # Q3
    opts["custom"] = ""                           # default empty custom list
    if opts["scope"] == "3":                      # custom chosen?
        opts["custom"] = ask("Custom ports (e.g. 22,80,443 or 1-1024):", "")   # read list
    opts["Pn"] = ask("Skip host discovery (-Pn)? [Y/n]", "y").lower().startswith("y")  # Q4
    t = ask("Timing (-T1 to -T5)? [1-5, default 4]:", "4")   # Q5 read timing
    opts["T"] = t if t in ("1", "2", "3", "4", "5") else "4" # validate
    return opts                                   # hand back the answers


def build_nmap_args(o):
    """Convert the answer dictionary into an ordered nmap argument list."""
    args = []                                     # start empty
    if o["sV"]:                                   # version detection wanted?
        args.append("-sV")                        # add -sV
    if o["sC"]:                                   # default scripts wanted?
        args.append("-sC")                        # add -sC
    if o["scope"] == "2":                         # full port range chosen?
        args += ["-p-"]                           # add -p- (all 65535)
    elif o["scope"] == "3" and o["custom"]:       # custom list and non-empty?
        args += ["-p", o["custom"]]               # add -p <list>
    if o["Pn"]:                                   # skip host discovery?
        args.append("-Pn")                        # add -Pn
    args.append(f"-T{o['T']}")                    # always add timing template
    return args                                   # return the flag list


def nmap_module(target, args):
    """Run nmap, parse its XML and print a clean, bullet-point port map."""
    section(7, "nmap port & service map")         # section header

    if not shutil.which("nmap"):                  # nmap is mandatory
        bullet("nmap", "NOT INSTALLED — run: sudo apt install nmap")   # warn
        return                                    # stop module

    if os.geteuid() != 0:                         # privilege note only
        bullet("Note", "not root — SYN scan and OS detection unavailable")   # warn

    cmd = ["nmap"] + args + ["-oX", "-", target]  # -oX - streams XML to stdout
    bullet("Command", " ".join(cmd))              # print the exact command

    raw, err, rc = run(cmd, timeout=3600)         # allow up to one hour
    if not raw.lstrip().startswith("<?xml"):      # no parseable XML returned
        bullet("nmap", "no XML output — target unreachable or blocked")   # warn
        if err:                                   # any stderr?
            sub(err.splitlines()[0])              # show first error line
        return                                    # stop module

    try:                                          # XML may be malformed
        root = ET.fromstring(raw)                 # parse the XML document
    except ET.ParseError:                         # parse failure
        bullet("nmap", "XML parse failure")       # report
        return                                    # stop module

    finished = root.find("runstats/finished")     # scan timing block
    hosts = root.findall("host")                  # every host element
    up = [h for h in hosts                        # filter host list
          if h.find("status") is not None and h.find("status").get("state") == "up"]  # up only

    bullet("Hosts scanned", str(len(hosts)))      # count scanned hosts
    bullet("Hosts up", str(len(up)))              # count live hosts
    if finished is not None:                      # timing block present?
        bullet("Scan duration", f"{finished.get('elapsed', '?')}s")   # print elapsed

    for host in up:                               # one loop per live host
        ip, mac = None, None                      # reset per host
        for a in host.findall("address"):         # iterate address elements
            if a.get("addrtype") in ("ipv4", "ipv6"):   # IP address?
                ip = a.get("addr")                # network address
            elif a.get("addrtype") == "mac":      # MAC address?
                mac = f"{a.get('addr')} ({a.get('vendor', 'unknown')})"  # with vendor
        names = [n.get("name") for n in host.findall("hostnames/hostname")]  # PTR names

        times = host.find("times")                # timing element
        srtt = "n/a"                              # default latency text
        if times is not None and times.get("srtt"):   # srtt present?
            srtt = f"{int(times.get('srtt')) / 1000:.4f}s"   # microseconds -> seconds

        bullet("Host", f"{ip}  ({names[0] if names else 'no PTR'})")   # host bullet
        bullet("Latency", srtt)                   # latency bullet
        if mac:                                   # MAC present?
            bullet("MAC", mac)                    # MAC bullet

        for osm in host.findall("os/osmatch"):    # iterate OS matches
            acc = osm.get("accuracy", "?")        # accuracy percentage
            bullet("OS guess", f"{osm.get('name')}  ({acc}% confidence)")   # print
            break                                 # best match only

        ports = host.findall("ports/port")        # every port element
        open_ports = [p for p in ports            # filter open ports
                      if p.find("state") is not None
                      and p.find("state").get("state") == "open"]
        bullet("Open TCP ports", f"{len(open_ports)} of {len(ports)} scanned")  # count

        for p in open_ports:                      # iterate each open port
            portid = p.get("portid")              # e.g. "21"
            proto = p.get("protocol")             # "tcp"
            svc = p.find("service")               # <service .../>
            name = svc.get("name", "") if svc is not None else ""       # service name
            product = svc.get("product", "") if svc is not None else "" # product
            version = svc.get("version", "") if svc is not None else "" # version
            extrainfo = svc.get("extrainfo", "") if svc is not None else ""  # extra
            banner = " ".join(x for x in (product, version, extrainfo) if x) # banner

            print(f"    - {B}{I}{portid}/{proto}{R}  open  {name}"   # port line
                  + (f"  ·  {banner}" if banner else ""))            # optional banner

            if portid in PORT_RISK:               # known risky port?
                sev, msg = PORT_RISK[portid]      # unpack severity + message
                sub(f"{B}{I}[{sev}]{R} {style_split(msg)}")   # styled severity + msg
                FINDINGS.append((sev, f"{portid}/{proto} — {msg}"))   # record finding

            haystack = f"{name} {banner}"         # combined text to search
            for rx, sev, msg in VERSION_RISK:     # iterate fingerprint rules
                if rx.search(haystack):           # rule matched?
                    sub(f"{B}{I}[{sev}]{R} {style_split(msg)}")   # styled severity + msg
                    FINDINGS.append((sev, msg))      # record finding

            for script in p.findall("script"):    # iterate script elements
                lines = [l for l in script.get("output", "").splitlines() if l.strip()]  # clean
                if not lines:                     # nothing to show?
                    continue                      # skip
                sub(f"NSE {script.get('id')}: {lines[0][:100]}")   # styled prefix
                for extra in lines[1:6]:          # next five lines
                    sub(extra[:100])              # plain extra line
                # Anonymous FTP is a real exposure — record it.
                if script.get("id") == "ftp-anon" and "anonymous" in lines[0].lower():
                    FINDINGS.append(("HIGH", "Anonymous FTP login permitted"))  # record

        for script in host.findall("hostscript/script"):   # host-level scripts
            lines = [l for l in script.get("output", "").splitlines() if l.strip()]  # clean
            if not lines:                         # nothing to show?
                continue                          # skip
            sub(f"Host script {script.get('id')}: {lines[0][:100]}")   # styled prefix
            for extra in lines[1:4]:              # next three lines
                sub(extra[:100])                  # plain extra line


# =============================================================================
#  [8] EXECUTIVE SUMMARY
# =============================================================================

def module_summary(target, report_path):
    """Condense every finding into a severity-ranked closing block."""
    section(8, "executive summary")               # section header

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}   # sort order
    counts = {}                                   # severity tally
    for sev, _ in FINDINGS:                       # iterate findings
        counts[sev] = counts.get(sev, 0) + 1      # tally per severity

    bullet("Target", target)                      # print target
    bullet("Total findings", str(len(FINDINGS)))  # total count
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):   # per-severity counts
        if counts.get(sev):                       # only if present
            bullet(f"{sev} findings", str(counts[sev]))  # print tally

    if counts.get("CRITICAL"):                    # highest severity present?
        verdict = "CRITICAL — remotely exploitable services are exposed"  # verdict
    elif counts.get("HIGH"):                      # else high?
        verdict = "HIGH — multiple high-impact exposures present"         # verdict
    elif counts.get("MEDIUM"):                    # else medium?
        verdict = "MEDIUM — hardening gaps, no trivially exploitable service"  # verdict
    else:                                         # else low
        verdict = "LOW — no significant exposure detected"                # verdict
    bullet("Verdict", verdict)                    # print the verdict

    print()                                       # blank line
    seen = set()                                  # de-duplication set
    for sev, msg in sorted(FINDINGS, key=lambda f: order.get(f[0], 9)):  # sorted
        if msg in seen:                           # duplicate message?
            continue                              # skip
        seen.add(msg)                             # remember it
        print(f"- {B}{I}[{sev}]{R} {style_split(msg)}")   # print finding

    print()                                       # blank line
    bullet("Report saved", report_path)           # announce report path


# =============================================================================
#  MAIN
# =============================================================================

def main():
    """Wire every module together into one sequential recon workflow."""
    banner()                                      # print the identity block

    for tool in ("curl", "nmap"):                 # hard requirements
        if not shutil.which(tool):                # missing?
            print(f"{B}{I}[!] missing required tool: {tool}{R}")   # warn
            sys.exit(1)                           # abort

    target = ask("Target (IP or domain):", "")    # collect the target
    if not target:                                # empty target?
        print(f"{B}{I}[!] no target supplied — aborting{R}")   # warn
        sys.exit(1)                               # abort

    opts = nmap_options()                         # ask the five nmap questions up front
    nmap_args = build_nmap_args(opts)             # auto-build the flag list

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)   # filesystem-safe name
    report_path = f"subfinder_{safe}_{datetime.now():%Y%m%d_%H%M%S}.txt"   # report name
    tee = Tee(report_path)                        # open the tee
    sys.stdout = tee                              # every print() now tees

    module_public_ip()                            # [1] curl egress IP
    module_ifconfig()                             # [2] local interfaces
    module_subfinder(target)                      # [3] passive subdomain enum
    module_http(target)                           # [4] curl HTTP header audit
    module_whatweb(target)                        # [5] web fingerprint
    module_whois(target)                          # [6] registry lookup
    nmap_module(target, nmap_args)                # [7] nmap runs LAST
    module_summary(target, report_path)           # [8] executive summary

    sys.stdout = sys.__stdout__                   # restore stdout
    tee.close()                                   # close the report file
    print(f"\n{B}{I}Recon workflow finished.{R}") # closing line


# Standard Python entry-point guard.
if __name__ == "__main__":
    main()