nmap - answer simply, the flags are built for you
Scan technique:
    [1] -sS  SYN stealth scan (needs root, default, fastest)
    [2] -sT  TCP connect scan (no root needed, uses connect())
    [3] -sA  ACK scan (maps firewall rules, no port state)
    [4] -sW  Window scan (TCP window size, distinguishes open/closed)
    [5] -sN  NULL scan (no TCP flags set, evades some filters)
    [6] -sF  FIN scan (only FIN set, evades some filters)
    [7] -sX  Xmas scan (FIN+PSH+URG set, evades some filters)
    [8] -sU  UDP scan (slow, finds DNS/SNMP/DHCP services)
Choose scan technique [1-8, default 1]: 2
Version + service detection (-sV)? [Y/n] y
Default NSE scripts (-sC)? [y/N] n
Ports: [1] top-1000  [2] all 65535 (-p-)  [3] custom (-p)  [1] 1
Skip host discovery (-Pn)? [Y/n] y
Timing (-T1 to -T5)? [1-5, default 4]: 4
