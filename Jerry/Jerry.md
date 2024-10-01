## HTB Jerry

### Enumeration

I'll start off with a basic nmap script. Jerry just has 1 port open 8080.

![nmap](/Jerry/images/nmap.png) 

![nmap](/Jerry/images/nmap2.png) 

It looks like Jerry is runny Apache Tomcat. I'll start with a dirbuster scan for directories.

If we try to go to the manager endpoint it asks us for a username and a password but after an unsuccessful login we get a 401 Unauthorized page that has the credentials in it.

Username: tomcat
Password: s3cret

![nmap](/Jerry/images/creds.png) 

And sure enough it works.

![nmap](/Jerry/images/login.png) 

Now that we have access to the manager console we can use msfvenom to create a war file and upload and deploy it on the Server.

![nmap](/Jerry/images/payload.png) 

I'll start a listener on my attack box and deploy our war file.

![nmap](/Jerry/images/deploy.png) 

As soon as we click on our deployed shell we get a call back on our listener and we are already running as NT AUTHORITY SYSTEM.

![nmap](/Jerry/images/launch.png) 

That was a fun and easy box ;)

![nmap](/Jerry/images/root.png) 
