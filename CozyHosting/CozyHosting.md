## HTB CozyHosting (10.129.229.88)

### Enumeration

ports 22, 80 are open

	Nmap scan report for 10.129.229.88
	Host is up (0.053s latency).

	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
	|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
	80/tcp open  http    nginx 1.18.0 (Ubuntu)
	|_http-title: Did not follow redirect to http://cozyhosting.htb
	|_http-server-header: nginx/1.18.0 (Ubuntu)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), Linux 5.3 - 5.4 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	Network Distance: 2 hops
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 443/tcp)
	HOP RTT      ADDRESS
	1   50.52 ms 10.10.14.1
	2   52.10 ms 10.129.229.88

	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	# Nmap done at Mon Sep 30 12:43:27 2024 -- 1 IP address (1 host up) scanned in 12.18 seconds


#### port 80 is not following redirects.

we can add IP 10.129.229.88  cozyhosting.htb to /etc/hosts to resolve this.

![Hosts](/CozyHosting/images/hosts.png) 


![Webpage](/CozyHosting/images/webpage.png) 

Visiting the webpage looks like an nginx server on ubuntu OS. We also have a logon page that gives us 'Invalid username or password' if we try to login with admin:admin

![Webpage](/CozyHosting/images/login.png) 

Enumerating the error page of the website lets me know it's running Spring Boot. I'll run feroxbuster with the spring boot wordlist and we get some /acuator endpoints.

![Webpage](/CozyHosting/images/error.png) 

![Webpage](/CozyHosting/images/feroxbuster.png) 


	cat directory.txt | grep "/actuator"                         
	200      GET        1l        1w      634c http://cozyhosting.htb/actuator
	404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
	404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
	404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
	200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
	200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
	404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
	200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
	200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
	200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
	200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
	404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/spring.jmx.enabled
	200      GET        1l        1w       48c http://cozyhosting.htb/actuator/sessions
	200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings


The /actuator/sessions gives me a username and a cookie value.


![Webpage](/CozyHosting/images/sessions.png) 

If I add kanderson's cookie to the JSESSIONID I am able to access the Admin dashboard.

![Webpage](/CozyHosting/images/admin.png) 

We can try a simple ping command to see if we can do a command injection. The form field doesn't like spaces so I have to use the linux ${IFS} varible instead of spaces but it seems to work.

![Webpage](/CozyHosting/images/injection-test.png) 


![Webpage](/CozyHosting/images/wireshark.png) 



I create a simple bash reverse shell and I'll use burp repeater to curl my shell and execute it on the host.

![Webpage](/CozyHosting/images/shell.png) 

![Webpage](/CozyHosting/images/burp.png) 

I'll now execute bash /tmp/shell.sh and start a listener on my local host.

![Webpage](/CozyHosting/images/netcat.png) 


### Upgrade shell

1. script /dev/null -c bash
2. ctrl + Z
3. stty raw -echo; fg
4. press Enter
5. type reset
4. type screen
5. stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'
6. stty rows ROWS cols COLS

And now you have a fully interactive shell.

In the /app directory we can see the .jar Java file the Webpage is using for it's source code. If we copy it to /dev/shm and unzip it we can dig into it some more.

![Webpage](/CozyHosting/images/app.png) 


If we read the MANIFEST file it will show us the entry point for the application

![Webpage](/CozyHosting/images/manifest.png) 

grepping for password give me the /boot/classes/application.properties file which I find a password for postgresql.

Password: Vg&nvzAQ7XxR

![Webpage](/CozyHosting/images/grep.png) 

I am able to login to postgres on the host let's look around

![Webpage](/CozyHosting/images/psql.png) 


There's a database called cozyhosting and a user's table inside the database.

![Webpage](/CozyHosting/images/data.png) 

The user's table contains a hash for admin and kanderson. I'll copy these to my attack machine and see if I can crack them.

![Webpage](/CozyHosting/images/hash.png) 


$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm

These look like bcrypt hashes I'll try and crack them with JtR.

If I am able to crack one of the hashes it is most likely either for root or josh.

![Webpage](/CozyHosting/images/josh.png) 

One of the hashes finally crackes and it is:

manchesterunited

I already have a shell as app I'm just going to see if I can su to josh using the password.

![Webpage](/CozyHosting/images/user.png) 

It works and we now have a shell as josh and can grab the user.txt file.


### Privilege Escalation

checking Josh's sudo privilege's i see he can run anything with /usr/bin/ssh. gtfobins has a great priv esc for this.

![Webpage](/CozyHosting/images/ssh.png) 

Lucky for us privilege escalation is straight out of [gtfobins](https://gtfobins.github.io/gtfobins/ssh/) for sudo use of SSH.

![Webpage](/CozyHosting/images/priv-esc.png) 

It works like a charm and we are root!

![Webpage](/CozyHosting/images/root.png) 
