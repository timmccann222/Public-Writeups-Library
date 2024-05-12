# ServMon

## Enumeration

NMAP Scan - All Ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report "10.10.10.184"

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 127
22/tcp    open  ssh          syn-ack ttl 127
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
6063/tcp  open  x11          syn-ack ttl 127
6699/tcp  open  napster      syn-ack ttl 127
8443/tcp  open  https-alt    syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49670/tcp open  unknown      syn-ack ttl 127
```

NMAP Scan Port Services:

```bash
nmap -sV -sC -Pn -v -oN nmap-report "10.10.10.184" -p 21,22,80,135,139,445,6063,6699,8443,49667,49670


```
