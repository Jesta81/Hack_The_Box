##   Hack The Box      Netmon (10.129.10.129)

### Enumeration

I'll start off with an nmap scan of all tcp ports.


	PORT      STATE SERVICE      REASON          VERSION
	21/tcp    open  ftp          syn-ack ttl 127 Microsoft ftpd
	| ftp-anon: Anonymous FTP login allowed (FTP code 230)
	| 02-03-19  12:18AM                 1024 .rnd
	| 02-25-19  10:15PM       <DIR>          inetpub
	| 07-16-16  09:18AM       <DIR>          PerfLogs
	| 02-25-19  10:56PM       <DIR>          Program Files
	| 02-03-19  12:28AM       <DIR>          Program Files (x86)
	| 02-03-19  08:08AM       <DIR>          Users
	|_11-10-23  10:20AM       <DIR>          Windows
	| ftp-syst: 
	|_  SYST: Windows_NT
	80/tcp    open  http         syn-ack ttl 127 Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
	|_http-server-header: PRTG/18.1.37.13946
	| http-title: Welcome | PRTG Network Monitor (NETMON)
	|_Requested resource was /index.htm
	|_http-trane-info: Problem with XML parsing of /evox/about
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
	135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
	139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
	5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
	49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
	49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
	49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
	49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 (93%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows 10 1511 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/5%OT=21%CT=%CU=41395%PV=Y%DS=2%DC=T%G=N%TM=67015F54%P=aarch64-unknown-linux-gnu)
	SEQ(SP=106%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=A)
	OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)
	WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
	ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=Y%Q=)
	T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
	T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
	T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
	T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
	T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
	IE(R=Y%DFI=N%T=80%CD=Z)

	Uptime guess: 0.015 days (since Sat Oct  5 10:24:31 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=262 (Good luck!)
	IP ID Sequence Generation: Incremental
	Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

	Host script results:
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
	| p2p-conficker: 
	|   Checking for Conficker.C or higher...
	|   Check 1 (port 63193/tcp): CLEAN (Couldn't connect)
	|   Check 2 (port 18461/tcp): CLEAN (Couldn't connect)
	|   Check 3 (port 41285/udp): CLEAN (Failed to receive data)
	|   Check 4 (port 57302/udp): CLEAN (Timeout)
	|_  0/4 checks are positive: Host is CLEAN or ports are blocked
	|_clock-skew: mean: 5s, deviation: 0s, median: 5s
	| smb2-time: 
	|   date: 2024-10-05T15:46:30
	|_  start_date: 2024-10-05T15:24:46
	| smb-security-mode: 
	|   account_used: guest
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)

	TRACEROUTE (using port 21/tcp)
	HOP RTT      ADDRESS
	1   60.68 ms 10.10.14.1
	2   60.72 ms 10.129.10.129

	Read data files from: /usr/share/nmap
	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .


This box has a lot of open ports. Looks like we have anon access to FTP, web (80), netbios, SMB, and winrm. I'll start off seeing what all I can find on the FTP server.

### FTP Enum

Right away I am able to find the user flag on the Public User's Desktop. There are only 2 users on this box Public and Admin. I also find to lnk files for PRTG Network Monitor in Public User's Desktop. This box must be using the software but I'm not familiar with it.


![Website](/Netmon/images/web.png) 


There is a login page hosted a /public/login.htm and it looks like this is just your basic network monitoring software. I googled online for known exploits and there are quite a few but they all require you to be authenticated. I tried the default user:password combo of prtgadmin:prtgadmin and that didn't work. :(

Fortunately for me I found a website that shows us how us an unathenticated user we can create a user account with PRTG Network Monitoring software. [Here is a link to the exploit to create a user](https://medium.com/@qdoan95/building-an-exploit-for-cve-2018-19410-1475f555f74c). 

To make this exploit work we need to make a POST request to "/public/login.htm", passing "/api/addusers.htb" to the "file" parameter with the "id" and "users" captured from the authenticated request in the request body.

Here is an example of what the post request would look like.


![Website](/Netmon/images/burp.png) 


The exploit seemed to be working but I still wasn't able to login. Googling some more about PRNG I found out where it's configuration files are stored at on the OS and I pulled them out of my FTP session so I can examine them to see if I can find a username or a password.


![Website](/Netmon/images/ftp.png) 


In the ProgramData\Paessler\PRTG Network Monitor directory I saw and old .bak configuration file. After a bit I was able to find a username and password in the file.


![Website](/Netmon/images/password.png) 

Username: prtgadmin 

Password: PrTg@dmin2018

However, the creds don't work to login to the website. This is an old box and after hours of enumeration of finally just created a wordlist with PrTg@dmin2018 that increments by a year until 2024 and finally I got a password of PrTg@dmin2019 that does work to login to the console. So now we do have the following working credentials.

Username: prtgadmin

Password: PrTg@dmin2019


### Foothold


We can now login to the admin dashboard. 

![Website](/Netmon/images/admin-web.png) 

Used used searchsploit and just searched network monitor and I see one that is a bash script for authenticated Remote Code Execution. Now that we have working credentials let's download the bash script and take a look at how it works.

![Website](/Netmon/images/foothold.png) 


The exploit creates a batch script and uploads it to C:\Users\Public\tester.txt the batch file then uses PowerShell to add a user to the host and then it creates an admin user named 'pentest' with a password of 'P3nT3st' and adds them to the Administrators group. Let's try it out and see it it works.


I added the value of my admin cookie to the script and it seemed to work. I also noticed port 5985 is open on this box. I should be able to just use evil-winrm with the creds 'pentest' 'P3nT3st' and have an admin shell.


![Website](/Netmon/images/priv.png) 


### Priv Esc

running evil-winrm with the user and credentials I have works and I have access to the Administrator directory and can grab the root flag. I am running as the user pentest though but he is in the Administrators group.

![Website](/Netmon/images/evil-winrm.png) 


![Website](/Netmon/images/group.png) 
