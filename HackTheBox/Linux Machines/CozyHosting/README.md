# CozyHosting

# User Flag

## NMAP Enumeration

Masscan UDP/TCP Port Scan:

```bash
sudo masscan -p1-65535,U:1-65535 10.10.11.230 --rate=1000 -e tun0

N/A
```

NMAP All Open ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN nmap-report-all-open-ports 10.10.11.230

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

All Ports (Filtered, Closed, etc.)

```bash
sudo nmap -T5 -sS -vvv --min-rate=100 --max-retries=3 -p- -oN nmap-report-all-ports 10.10.11.230

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Port Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report-service-scan 10.10.11.230 -p 

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Service Enumeration (Port 80)

Web App Enumeration:

* Login Page - tried multiple default usernames and passwords but nothing worked.
* Email found `info@cozyhosting.htb`
* No developer comments on web page.

Directory Fuzzing with `ffuf` tool to find hidden directories:

```bash
ffuf -c -u http://cozyhosting.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 111ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 127ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 982ms]
admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 169ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 130ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 466ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 169ms]
27079%5Fclassicpeople2%2Ejpg [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 104ms]
children%2527s_tent     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 161ms]
tiki%2Epng              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 77ms]
Wanted%2e%2e%2e         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 74ms]
How_to%2e%2e%2e         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 86ms]
squishdot_rss10%2Etxt   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 108ms]
b33p%2Ehtml             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 73ms]
help%2523drupal         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 102ms]
```

While working through the directories above, an error Page indicates [Spring Boot](https://stackoverflow.com/questions/31134333/this-application-has-no-explicit-mapping-for-error) is being used:

![Error Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/CozyHosting/Images/Error%20Page.png)

Performed an additional web enumeration with `ffuf` using `/usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt`:

```bash
ffuf -c -u http://cozyhosting.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt -ic

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 144ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 116ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 129ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 130ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 227ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 230ms]
actuator/sessions       [Status: 200, Size: 48, Words: 1, Lines: 1, Duration: 196ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 522ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 143ms]
```

I can see that the `actuator` directory is returned and a search online returns multiple [exploits](https://github.com/pyn3rd/Spring-Boot-Vulnerability) for exposed Actuator endpoints. Looking through the `actuator/sessions` directory, I can see a session for the user `kanderson`

```bash
{"AFE0D93E8A1C956408BE89B8D6BA71B7":"kanderson"}
```

If I edit the session cookie value and replace it with Kanderson's session, I can now visit the `admin` page.

![Admin Dashboard](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/CozyHosting/Images/Admin%20Dashboard.png)

There is a feature at the bottom of the page that allows us enter input which is executed on the target. The error message indicates an ssh connection is being performed.

![Admin Page Functionality](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/CozyHosting/Images/Admin%20Page%20Functionality.png)

In BurpSuite, I can see the POST request is made to `/executessh`, which also indicates that an ssh connection is being made but also indicates that the ssh command might be involved.

```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin?error=Invalid%20hostname!
Cookie: JSESSIONID=0A81A5F2D9476C0A8D2199EF85FB5EF9
Upgrade-Insecure-Requests: 1

host=10.0.0.1&username=test
```









