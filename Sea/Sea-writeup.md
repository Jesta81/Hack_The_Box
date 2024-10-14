## Hackthebox Sea Writeup

## Enumeration

### Bash nmap script

	PORT   STATE SERVICE REASON         VERSION
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZDkHH698ON6uxM3eFCVttoRXc1PMUSj8hDaiwlDlii0p8K8+6UOqhJno4Iti+VlIcHEc2THRsyhFdWAygICYaNoPsJ0nhkZsLkFyu/lmW7frIwINgdNXJOLnVSMWEdBWvVU7owy+9jpdm4AHAj6mu8vcPiuJ39YwBInzuCEhbNPncrgvXB1J4dEsQQAO4+KVH+QZ5ZCVm1pjXTjsFcStBtakBMykgReUX9GQJ9Y2D2XcqVyLPxrT98rYy+n5fV5OE7+J9aiUHccdZVngsGC1CXbbCT2jBRByxEMn+Hl+GI/r6Wi0IEbSY4mdesq8IHBmzw1T24A74SLrPYS9UDGSxEdB5rU6P3t91rOR3CvWQ1pdCZwkwC4S+kT35v32L8TH08Sw4Iiq806D6L2sUNORrhKBa5jQ7kGsjygTf0uahQ+g9GNTFkjLspjtTlZbJZCWsz2v0hG+fzDfKEpfC55/FhD5EDbwGKRfuL/YnZUPzywsheq1H7F0xTRTdr4w0At8=
	|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMoxImb/cXq07mVspMdCWkVQUTq96f6rKz6j5qFBfFnBkdjc07QzVuwhYZ61PX1Dm/PsAKW0VJfw/mctYsMwjM=
	|   256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHuXW9Vi0myIh6MhZ28W8FeJo0FRKNduQvcSzUAkWw7z
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	| http-cookie-flags: 
	|   /: 
	|     PHPSESSID: 
	|_      httponly flag not set
	|_http-title: Sea - Home
	|_http-server-header: Apache/2.4.41 (Ubuntu)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=8/27%OT=22%CT=%CU=42852%PV=Y%DS=2%DC=T%G=N%TM=66CDEFB2%P=aarch64-unknown-linux-gnu)
	SEQ(SP=108%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)
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

	Uptime guess: 47.455 days (since Wed Jul 10 23:29:09 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=264 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	
### Web enumeration (port 80)

> - dirsearch -u http://sea.htb -o base-directory.txt -t 50

	cat base-directory.txt | grep 200    
	200     1KB  http://sea.htb/404
	200   939B   http://sea.htb/contact.php

	cat base-directory.txt | grep 301
	301   228B   http://sea.htb/data    -> REDIRECTS TO: http://sea.htb/data/
	301   232B   http://sea.htb/messages    -> REDIRECTS TO: http://sea.htb/messages/
	301   231B   http://sea.htb/plugins    -> REDIRECTS TO: http://sea.htb/plugins/
	301   230B   http://sea.htb/themes    -> REDIRECTS TO: http://sea.htb/themes/
	200     1KB  http://sea.htb/themes/404
	200     1KB  http://sea.htb/themes/admin/home
	200     1KB  http://sea.htb/themes/home
	200     1KB  http://sea.htb/themes/sitecore/content/home
	200     1KB  http://sea.htb/themes/sym/root/home/

Username: amay@sea.htb
Password: mychemicalromance
