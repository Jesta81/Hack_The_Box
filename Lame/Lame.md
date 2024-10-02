## Hackthebox Lame (10.129.212.63) 

### Enumeration

nmap scan

A quick initial nmap scan shows us 5 ports open on the host: 21,22,139,445,3622

![nmap](/Lame/images/nmap.png) 

#### Full nmap scan of open ports

	PORT     STATE SERVICE     VERSION
	21/tcp   open  ftp         vsftpd 2.3.4
	|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
	| ftp-syst: 
	|   STAT: 
	| FTP server status:
	|      Connected to 10.10.14.240
	|      Logged in as ftp
	|      TYPE: ASCII
	|      No session bandwidth limit
	|      Session timeout in seconds is 300
	|      Control connection is plain text
	|      Data connections will be plain text
	|      vsFTPd 2.3.4 - secure, fast, stable
	|_End of status
	22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
	| ssh-hostkey: 
	|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
	|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
	139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
	445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
	3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Aggressive OS guesses: Linux 2.6.23 (91%), DD-WRT v24-sp1 (Linux 2.4.36) (90%), Arris TG862G/CT cable modem (90%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (90%), Dell Integrated Remote Access Controller (iDRAC6) (90%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (90%), Linux 2.4.21 - 2.4.31 (likely embedded) (90%), Linux 2.4.27 (90%), Linux 2.4.7 (90%), Citrix XenServer 5.5 (Linux 2.6.18) (90%)
	No exact OS matches for host (test conditions non-ideal).
	Network Distance: 2 hops
	Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

	Host script results:
	|_smb2-time: Protocol negotiation failed (SMB2)
	|_clock-skew: mean: 2h00m37s, deviation: 2h49m44s, median: 35s
	| smb-os-discovery: 
	|   OS: Unix (Samba 3.0.20-Debian)
	|   Computer name: lame
	|   NetBIOS computer name: 
	|   Domain name: hackthebox.gr
	|   FQDN: lame.hackthebox.gr
	|_  System time: 2024-10-02T14:20:19-04:00
	| smb-security-mode: 
	|   account_used: guest
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)

	TRACEROUTE (using port 445/tcp)
	HOP RTT      ADDRESS
	1   62.60 ms 10.10.14.1
	2   63.54 ms 10.129.212.63

Noting from the nmap scan ftp allows anonymous login.

Script results gives us the following information.

Computer Name: lame
Domain Name: hackthebox.gr
FQDN: lame.hackthebox.gr


### Enumerating SMB

enumerating smb shows the following shares and that we have read / write to the tmp share.

![smb](/Lame/images/smbmap.png) 

### Foothold

There is a particular metasploit module that creates a symbolic link to root through smb if you have write permission on a share. Let's see if it will work on Lame.

This is the module that I'll want to use, I'll just have to set the RHOST value of Lame's IP and the Share of /tmp.

![metasploit](/Lame/images/metasploit.png) 

It worked and we now should have access to /root

![metasploit](/Lame/images/foothold.png) 

### Priv Esc

Using smbclient and connecting to the /tmp share I can now access the rootfs share and I have access to all the root directories and can now grab all the flags. :)

![metasploit](/Lame/images/root.png) 

I could've just gotten all the flags through my SMB session however, I could also plant backdoors and other things for persistence. I decided to grab the root accounts ssh key so now I should have ssh access to Lame from my attack box.

![SMB](/Lame/images/ssh.png) 

ssh-keygen -b 4096 -t rsa -f lame

I fiddled around trying to generate ssh keys and put them in the root account and to run a netcat shell out of /tmp but nothing really worked. I finally resorted to this metasploit module and was able to was root access on Lame.

![Root](/Lame/images/pwn.png) 
