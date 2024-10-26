## Hack The Box -- Instant 

## Enumeration 

- I'll start out with an nmap scan of the IP. 10.129.222.104 and it shows ports 22, and 80 open. Port 80 is also not following redirects to http://instant.htb. So I'll add the IP and hostname to my /etc/hosts file. 


	PORT   STATE SERVICE REASON         VERSION
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMM6fK04LJ4jNNL950Ft7YHPO9NKONYVCbau/+tQKoy3u7J9d8xw2sJaajQGLqTvyWMolbN3fKzp7t/s/ZMiZNo=
	|   256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+zjgyGvnf4lMAlvdgVHlwHd+/U4NcThn1bx5/4DZYY
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.58
	|_http-title: Did not follow redirect to http://instant.htb/
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-server-header: Apache/2.4.58 (Ubuntu)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/21%OT=22%CT=%CU=39112%PV=Y%DS=2%DC=T%G=N%TM=6716C6C3%P=aarch64-unknown-linux-gnu)
	SEQ(SP=102%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
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

	Uptime guess: 12.830 days (since Tue Oct  8 20:30:50 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=258 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE (using port 80/tcp)
	HOP RTT      ADDRESS
	1   61.87 ms 10.10.14.1
	2   61.92 ms 10.129.222.104


### Website enumeration

- If we load http://instant.htb in a web browser we get a screen where we can download the source code of the web server. It looks like an Android application as the download is an apk file.


![web](/Instant/images/web.png) 


- We can either unpack them with unzip or apktook d <apk-file-name>. After unzipping them I did a recursive grep on instant.htb and found 2 additional subdomains.

1. swagger-ui.instant.htb
2. mywalletv1.instant.htb


![web](/Instant/images/subdomains.png) 


I'll add these 2 subdomains to my /etc/hosts file.


![hosts](/Instant/images/host-file.png) 



- Looking through the java source code we can see a Java Web Token (JWT) that looks like its used for Authorization.


	invoke-direct {v1}, Lokhttp3/Request$Builder;-><init>()V
		                                                                                                                           
	    const-string v2, "http://mywalletv1.instant.htb/api/v1/view/profile"
		                           
	    .line 24
	    invoke-virtual {v1, v2}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;
		                           
	    move-result-object v1

	    const-string v2, "Authorization"

	    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtO
	WQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"


- So now we can 2 new subdomains to enumerate and a JWT that is used for Authorization.

- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtO
WQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA


#### Subdomains

- All of the endpoints on the mywalletv1 subdomain /api /api/v1 /api/v1/view give us 404 Not Found responses. However the /api/v1/view/profile endpoint gives us a 401 Unathorized response. 


![response](/Instant/images/401.png) 

- If we look at some of the responses in burp we can see it's running Python Werkzeug v 3.0.3


![burp](/Instant/images/burp.png) 





### Foothold

- curl -X GET "http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H "accept: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOT
AwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"


- If we try a directory traversal against the log endpoing of the mywalletv1 subdomain we can read the /etc/passwd file. So we have a directory traveral vulnerability.


![lfi](/Instant/images/dir-trav.png) 


- Looking through the output we notice 2 users root and shirohige. Maybe we can try a directory traversal to read shirohige's ssh private key. /home/shirohige/.ssh/id_rsa 


- And it works to read shirohige's private ssh key. 


![foothold](/Instant/images/foothold.png) 


- With the ssh key we can now ssh into instant as the user shirogige. We don't known the password so running sudo -l does us no good.

![user](/Instant/images/ssh.png) 


![bash](/Instant/images/bash.png) 


### Priv Escalation

- After getting SSH access with shirohige's private key. I notice an application called 'Solar-PuTTY' located in /opt/backups. 

- After some Google searching it looks like Solar-Putty is a SolarWinds application that acts as a standalone free terminal emulator and network file transfer tool based on the well-known PuTTY for Windows. This [SolarWinds](https://www.solarwinds.com/assets/solarwinds/swdcv2/free-tools/solar-putty/resources/solar-putty-datasheet.pdf) site gives an indepth explanation of the tool / application. There is also a sessions-backup.dat file located in the /Solar-PuTTY directory. Some google searching shows a way to decrypt these .dat files on [github](https://github.com/VoidSec/SolarPuttyDecrypt). Here is a link to the complied version if you don't want to hassle with [compling the c Sharp code](https://github.com/VoidSec/SolarPuttyDecrypt/releases/tag/v1.0).  However, the program requires a 'Secret Key' that we don't have at this time.


![solar-putty](/Instant/images/solar-putty.png) 



- If we look in shirohige's home directory there are 2 directories /projects and /logs. There isn't anything interesting in /logs but if we dig arount in the /projects subfolders and directories we can find the following directory path ~/projects/mywallet/Instant-Api/mywallet contains all the application files for the application running on the mywalletv1.instant.htb domain. There's also a Docker .env file that contains a 'Secret Key'. We need a secret key to run with our SuperPutty cracker program. Let's see if this is the Secret Key.


	shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ cat .env 
	SECRET_KEY=VeryStrongS3cretKeyY0uC4NTGET

![secret key](/Instant/images/key.png) 


- The decryptor is written in c# and I'll have to switch to a windows VM to be able to try and crack the .dat file. I'm going to try with the secret key that we found above. 

- I opened my Windows 11 and ran the .\SolarPuTTY executable file against the sessions-backup.dat file and it gave me the following as the decrypted password '12**24nzC!r0c%q12'. 


![decrypt](/Instant/images/root-password.png) 


- I tried to ssh in as the user root with the password of estrealla put that doesn't work. However, if I have a working SSH session as shirohige I can just su root and paste of type in the password that was retrieved from running the Solar-PuTTY decryptor and we get a root shell! 



![root](/Instant/images/root.png) 
