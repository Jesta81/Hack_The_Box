## Hack The Box -- Tabby | 10.129.45.172


### Enumeration

I'll start off with an nmap scan of the host IP. Nmap scan shows us ports 22, 80, and 8080 are open.

	PORT     STATE SERVICE REASON         VERSION
	22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDv5dlPNfENa5t2oe/3IuN3fRk9WZkyP83WGvRByWfBtj3aJH1wjpPJMUTuELccEyNDXaUnsbrhgH76eGVQAyF56DnY3QxWlt82MgHTJWDwdt4hKMDLNKlt+i+sElqhYwXPYYWfuApFKiAUr+KGvnk9xJrhZ9/bAp+rW84LyeJOSZ8iqPVAdcjve5As1O+qcSAUfIHlZGRzkVuUuOq2wxUvegKsYnmKWUZW1E/fRq3tJbqJ5Z0JwDklN21HR4dmM7/VTHQ/AaTl/JnQxOLFUlryXAFbjgLa1SDOTBDOG72j2/II2hdeMOKN8YZN9DHgt6qKiyn0wJvSE2nddC2BbnGzamJlnQaXOpSb3+WDHP+JMxQJQrRxFoG4R6X2c0rx+yM5XnYHur9cQXC9fp+lkxQ8TtkMijbPlS2umFYcd9WrMdtEbSeKbaozi9YwbR9MQh8zU2cBc7T9p3395HAWt/wCcK9a61XrQY/XDr5OSF2MI5ESVG9e0t8jG9Q0opFo19U=
	|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDeYRLCeSORNbRhDh42glSCZCYQXeOAM2EKxfk5bjXecQyV5W7DYsEqMkFgd76xwdGtQtNVcfTyXeLxyk+lp9HE=
	|   256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHA/3Dphu1SUgMA6qPzqzm6lH2Cuh0exaIRQqi4ST8y
	80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
	|_http-server-header: Apache/2.4.41 (Ubuntu)
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Mega Hosting
	|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
	8080/tcp open  http    syn-ack ttl 63 Apache Tomcat
	| http-methods: 
	|_  Supported Methods: OPTIONS GET HEAD POST
	|_http-title: Apache Tomcat
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/7%OT=22%CT=%CU=40397%PV=Y%DS=2%DC=T%G=N%TM=670428E9%P=aarch64-unknown-linux-gnu)
	SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
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

	Uptime guess: 36.704 days (since Sat Aug 31 20:37:19 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=263 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 443/tcp)
	HOP RTT      ADDRESS
	1   63.06 ms 10.10.14.1
	2   64.17 ms 10.129.45.172

![nmap](/Tabby/images/nmap.png) 


On port 80 the Tabby website looks like a server / data hosting site. I'll run a feroxbuster scan against the site for directories.

![web](/Tabby/images/web.png)

On port 8080 we have a Tomcat home page installation with various paths to config files.

![tomcat](/Tabby/images/tomcat.png) 

Viewing the source code on Tabby it looks like the links are resolving to megahosting.htb. I'll add the IP and megahosting.htb to my /etc/hosts file.

![megahosting](/Tabby/images/megahosting.png)

![hosts](/Tabby/images/hosts.png)

I originally had the /etc/hosts file set to tabby.htb. I'll rerun my feroxbuster scans and see if the results diff now. ;)

If we try to access the Tomcat /manager page it asks for creds. I enter tomcat:tomcat and that doesn't work.

The page does say we might have access to the manager-gui with the following creds. tomcat:s3cret.

![tomcat](/Tabby/images/tomcat-creds.png)

If I try and access the /news.php page on port 80 it has a ?file=statement clause in the url. I try this for a directory traversal and am able to read the /etc/passwd file. It looks like theres another user ash.

![lfi](/Tabby/images/lfi.png)


![lfi](/Tabby/images/passwd.png)

If I do a directory traversal for /usr/share/tomcat9/etc/tomcat-users.xml I am able to find creds to the manager text based service located at /manager/text.

Username: tomcat

Password: 

![lfi](/Tabby/images/tomcat-users.png) 



	NOTE:  By default, no user is included in the "manager-gui" role required
	  to operate the "/manager/html" web application.  If you wish to use this app,
	  you must define such a user - the username and password are arbitrary. It is
	  strongly recommended that you do NOT use one of the users in the commented out
	  section below since they are intended for use with the examples web
	  application.
	-->
	<!--
	  NOTE:  The sample user and role entries below are intended for use with the
	  examples web application. They are wrapped in a comment and thus are ignored
	  when reading this file. If you wish to configure these users for use with the
	  examples web application, do not forget to remove the <!.. ..> that surrounds
	  them. You will also need to set the passwords to something appropriate.
	-->
	<!--
	  <role rolename="tomcat"/>
	  <role rolename="role1"/>
	  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
	  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
	  <user username="role1" password="<must-be-changed>" roles="role1"/>
	-->
	   <role rolename="admin-gui"/>
	   <role rolename="manager-script"/>
	   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
	</tomcat-users>
	


I can now make a curl request with the following and receive info back

	$ curl -u 'tomcat:$3cureP4s5w0rd123!' http://megahosting.htb:8080/manager/text/list


![curl](/Tabby/images/curl.png) 

![curl](/Tabby/images/deploy.png)

![curl](/Tabby/images/war.png) 

I think I can create a .war jsp file and place it on the server now with curl. Reading the documentation some and it even tells me how to. I can go to /manager/text/deploy?path=/jesta and there's a curl command --upload-file <file> that will let me upload my war file.


### Foothold

![foothold](/Tabby/images/foothold.png) 

I'll start a netcat listener on my host on port 443. And curl my endpoint with the ware file: http://megahosting.htb/jesta and it should return us a shell.

We get a shell returned as the tomcat user.

![shell](/Tabby/images/shell.png) 


I hate having the non interactive shells that we also land in out of netcat this is a great blog on how to get a [fully interactive shell](https://blog.mrtnrdl.de/infosec/2019/05/23/obtain-a-full-interactive-shell-with-zsh.html) 

1. python3 -c 'import pty;pty.spawn("/bin/bash")'
2. ctrl + z to backgroud the shell
3. stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/' 
> - To get the number of colums and rows
4. stty raw -echo; fg
> - you'll probably need to press enter twice after this command
5. stty rows ROWS cols COLS
6. export TERM=term-256color


And now we should have a fully interactive shell.

![shell](/Tabby/images/interactive.png) 


I transfered linpeas from my kali box to the target because I was having a hard time escalating privileges. Hopefully it will give me a clue because I am not able to access the user ash's home directory with the user flag.

![linpeas](/Tabby/images/linpeas.png) 

Right away I notice these 2 CVE's that linpeas found. Let's take a look at them and see what they are.

1. CVE-2021-4043
2. CVE-2021-3560

![Priv](/Tabby/images/priv.png) 

The first CVE is PwnKit. I cloned the repo from [github](https://github.com/ly4k/PwnKit) and compiled the c binary file on my attack box first and then transferred it to the target host. 

###

Privilege Escalation

![Compile](/Tabby/images/compile.png) 


Compiling PwnKit.

	$ gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC

This created a 32 and 64 bit binary. I transfered the 64 bit binary by starting a python server on my attack box and then using wget to get it from my attack box to the target.


![root](/Tabby/images/root.png) 

I then made sure the hashes were still the same on both files after the wget transfer. After I confirmed they were I added the executable flag to the binary and ran it and it dropped my straight into a root shell.

I don't need to try and elevate my privileges to ash and then to root I can just run the PwnKit exploit and go straight to root. 

![yes](/Tabby/images/yes.png) 
