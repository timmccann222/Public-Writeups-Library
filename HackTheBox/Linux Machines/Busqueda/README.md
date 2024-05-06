# Busqueda


## Enumeration

I started enumerating the target machine by performing a quick scan with NMAP to identify any open ports:

```bash
nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.208

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

The scan identified two ports open (i.e. port 22 and 80). Next, I used NMAP to identify the services running on each port and used the common NSE scripts to find any common vulnerabilities that I could exploit:

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Initial Foothold - Web Application Analysis

A website with the domain `searcher.htb` is being hosted on port 80. I edited the `/etc/hosts` file and navigated to `searcher.htb` in Firefox. In BurpSuite under the HTTP history tab, I can see the various HTTP Requests and Responses being sent while interacting with the application. The web application allows us to select a search engine and some test criteria. It then redirects us to that search engine.

In the HTTP Response `Server` header, I can see `Werkzeug/2.1.2 Python/3.10.6` which indicates python is installed on the server.

Used `ffuf` to enumerate hidden directories:

```bash
ffuf -c -u http://searcher.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -ic -o ffuf_fuzz_small.txt


```



# Resources

* [Werkzeug / Flask Debug](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)





















