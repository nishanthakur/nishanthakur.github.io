---
title: "TryHackMe - Mr Robot Box Walkthrough"
date: 2021-06-21 00:00:00 +0545
categories: [Red-Team, CTF]
tags: [pentesting, tryhackme, mr.robot, wordpress, privilege-escalation, suid, nmap, gobuster, ctf-walkthrough]
author: nishant_thakur
description: "Complete walkthrough of the TryHackMe Mr Robot CTF box. Learn WordPress exploitation, privilege escalation via SUID binaries, and capture all three flags in this medium-difficulty challenge."
pin: false
math: false
mermaid: false
---

## 1. Overview
Hello Everyone, hope you guys are doing well. In this blog post, I am going to introduce you to TryHackMe — an online hacking platform. Also, I will be elaborating how I captured all the flags located inside the Mr. Robot Box which was really a fun box to do. If you are stuck at any particular location feel free to navigate over those locations using the provided links.

## 2. Introduction to TryHackMe
TryHackMe is an online platform that teaches cybersecurity through short, gamified real-world labs. They have information for complete novices as well as seasoned hackers, with tutorials and challenges to accommodate various learning methods. One can simply register and start learning.

![TryHackMe](/assets/img/posts/mr-robot-box-walkthrough/1.webp)

## 3. Accessing the machines via OpenVPN
**Step 1:** Click on your profile icon and then click on the access button which takes you to [this URL](https://tryhackme.com/access).

**Step 2:** Over there, select the VPN server that is closest to your location and click on the “Download My Configuration File” button. A file `<Username>.ovpn` should be downloaded.


![TryHackMe](/assets/img/posts/mr-robot-box-walkthrough/2.webp)

**Step 3:** Open your terminal and type this command “openvpn <your configuration file name>”. When you run this you see lots of text, at the end, it will say Initialization Sequence Completed

**Step 4:** Connection should be established and you should be able to access the machines.

**Note:** Sometimes there might be issue with the downloaded connection pack. Consider regenerating and downloading the newer configuration pack in such scenarios.

Enough about TryHackMe VPN configuration, now let us start the walk-through of Mr Robot Box.

## 4. Introduction to Mr Robot Box
Mr. Robot is a free room created by Leon Johnson with having difficulty rating of Medium.
![Mr. Robot](/assets/img/posts/mr-robot-box-walkthrough/3.webp)

Let us begin the scanning and enumeration process.

## 5. Scanning using Nmap
A quick nmap scan was launched against the Mr. Robot box by executing the command `nmap -sC -sV -oA nmap/initials -vv 10.10.49.166`. Only two ports i.e. `80 (HTTP)` and `443 (HTTPS)` were found in an open state.

![Nmap Scan](/assets/img/posts/mr-robot-box-walkthrough/4.webp)

```bash
# Nmap 7.91 scan initiated Thu Jun  3 17:14:14 2021 as: nmap -sC -sV -oA nmap/initials -vv 10.10.123.186
Nmap scan report for 10.10.123.186
Host is up, received syn-ack ttl 60 (0.25s latency).
Scanned at 2021-06-03 17:14:15 +0545 for 82s
Not shown: 997 filtered ports
Reason: 997 no-responses
PORT    STATE  SERVICE  REASON         VERSION
22/tcp  closed ssh      reset ttl 60
80/tcp  open   http     syn-ack ttl 60 Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http syn-ack ttl 60 Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
| SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
| -----BEGIN CERTIFICATE-----
| MIIBqzCCARQCCQCgSfELirADCzANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA93
| d3cuZXhhbXBsZS5jb20wHhcNMTUwOTE2MTA0NTAzWhcNMjUwOTEzMTA0NTAzWjAa
| MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
| MIGJAoGBANlxG/38e8Dy/mxwZzBboYF64tu1n8c2zsWOw8FFU0azQFxv7RPKcGwt
| sALkdAMkNcWS7J930xGamdCZPdoRY4hhfesLIshZxpyk6NoYBkmtx+GfwrrLh6mU
| yvsyno29GAlqYWfffzXRoibdDtGTn9NeMqXobVTTKTaR0BGspOS5AgMBAAEwDQYJ
| KoZIhvcNAQEFBQADgYEASfG0dH3x4/XaN6IWwaKo8XeRStjYTy/uBJEBUERlP17X
| 1TooZOYbvgFAqK8DPOl7EkzASVeu0mS5orfptWjOZ/UWVZujSNj7uu7QR4vbNERx
| ncZrydr7FklpkIN5Bj8SYc94JI9GsrHip4mpbystXkxncoOVESjRBES/iatbkl0=
|_-----END CERTIFICATE-----Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
# Nmap done at Thu Jun  3 17:15:37 2021 -- 1 IP address (1 host up) scanned in 82.71 seconds
```

## 6. Enumerating Web Services
Web services running on both port `80 and 443` were accessed via web browser and upon certain enumeration, it was found that both of the pages were the same.

![web service](/assets/img/posts/mr-robot-box-walkthrough/5.webp)
_Accessing the web service running on port 80._

![web service](/assets/img/posts/mr-robot-box-walkthrough/6.webp)
_Accessing the web service running on port 443._

## 7. Executing Gobuster
I tried executing some of the commands shown in the web portal. Also, I tried executing some of the systems command such as id, whoami, and so on. All of the commands displayed an error message. After that, I decided to fire up gobuster for listing out associated directories by executing the command `gobuster dir -u http://10.10.49.166/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.log`.

![gobuster](/assets/img/posts/mr-robot-box-walkthrough/7.webp)
_Running gobuster tool for identifying accessible directories._

## 8. Accessing robots.txt file
While gobuster was running in the background, I manually tried to access some files such as .ssh, .git, .env, robots.txt, web.config, and so on. Luckily, I got access to the `robots.txt` file which showed two different files namely `fsociety.dic` and `key-1-of-3.txt`


![robots.txt](/assets/img/posts/mr-robot-box-walkthrough/8.webp)
_Accessing robots.txt file_

`Robots.txt` file includes those file paths that are disallowed for accessing via web crawling using web robots.

![key-1-of-3.txt](/assets/img/posts/mr-robot-box-walkthrough/9.webp)
_Accessing key-1-of-3.txt file_

I quickly accessed the `key-1-of-3.txt` file and got the first key.


## 9. Enumerating WordPress Site
After submitting the key, I had a look at gobuster result and saw three interesting links i.e. `/login`, `/admin`, `/wp-login`. I accessed these links and found that `/wp-login` was quiet interesting.

![wordpress](/assets/img/posts/mr-robot-box-walkthrough/10.webp)

I tried some default credentials like `admin:admin`, `admin:password`, and so on. But, none of these credentials worked.

![wget](/assets/img/posts/mr-robot-box-walkthrough/11.webp)

One thing about this login page was interesting. For every invalid login attempt it showed a message `Invalid username`. This message could be used for performing username enumeration.

![sublime](/assets/img/posts/mr-robot-box-walkthrough/12.webp)

I was curious about what could be the purpose of `fsociety.dic` file and downloaded it. I executed the `wc -c fsociety.doc` command which showed that it consists of `7,245,381 characters`. So I opened it in sublime text.


![fsociety.dic](/assets/img/posts/mr-robot-box-walkthrough/13.webp)


Upon going through the `fsociety.dic` file what I realized was that some words were repeated more than once.

![burpsuite](/assets/img/posts/mr-robot-box-walkthrough/14.webp)

So, I decided to sort this file and stored only the unique words in another file namely sorted-fsociety.dic file. This file had way less characters compared to the previous one.

![burpsuite](/assets/img/posts/mr-robot-box-walkthrough/15.webp)


I tried brute forcing the username using burp suite making use of sorted-fsociety.dic file. While it was running in the background, I again looked through the files and directories listed out by gobuster.


## 10. Identifying Login Credentials
As gobuster listed out `/license` file, I accessed the access it. The page simply displayed generic information `do you want a password or something ?`.

![creds](/assets/img/posts/mr-robot-box-walkthrough/16.webp)


However, I saw the scrollbar aside and scrolled down the page. I saw a string that was probably base64 encoded.


![decoding creds](/assets/img/posts/mr-robot-box-walkthrough/17.webp)

I quickly grabbed it and decoded it. Surprisingly, it displayed us a potential credential. I successfully logged into the WordPress login portal using that credential.


## 11. Logging into the Web Portal

![Web Portal](/assets/img/posts/mr-robot-box-walkthrough/18.webp)

The credentials were valid as we were redirected to the dashboard of the web application. Thus, the next task was to pop out reverse shell.

## 12. Popping out Reverse Shell
As I was logged in, I had permission to change the content of pages associated with the appearance section of the dashboard. I planned to insert the PHP reverse shell in the 404.php file.

![Web Portal](/assets/img/posts/mr-robot-box-walkthrough/19.webp)

Kali Linux has `php-reverse-shell.php` file by default. So I located it and copied its content to 404.php file.

![Edit Theme](/assets/img/posts/mr-robot-box-walkthrough/20.webp)

I changed the ip address and port number to `10.17.9.66` and `9001` respectively as I had set up netcat listener in that location.

![Edit Theme2](/assets/img/posts/mr-robot-box-walkthrough/21.webp)

The `404.php` file was edited successfully and it was time to check if we could get a reverse shell or not. I navigated to the URL `10.10.49.166/wp-admin/404.php`. The code executed successfully and a shell popped out in netcat listener.


![reverse shell](/assets/img/posts/mr-robot-box-walkthrough/22.webp)

I quickly listed out the content located in that particular location. It displayed two files namely key-2-of-3.txt and password.raw-md5. As I had access to the system as a daemon user, I could not read the contents of the key-2-of-3.txt file. So I read the content of the password.raw-md5. It showed following content


```bash
cat password.raw-md5 
robot:c3fcd3d76192e4007dfb496cca67e13b
```

It looked like a raw-md5 hash of robot’s user password. So I cracked it using (crackstation.net)[crackstation.net].

![crackstation](/assets/img/posts/mr-robot-box-walkthrough/23.webp)


## 13. Privilege Escalation
Till now I was not rooted in the box. So I thought that we could get the last key only after performing privilege escalation. I tried commands like “sudo -l” to list out any binaries that could be executed by robot user with sudo permission. Nothing interesting was identified. Then I started to look for files that have `SUID` permission set.


![find](/assets/img/posts/mr-robot-box-walkthrough/24.webp)

There were numerous binaries whose SUID permission was set and among them, nmap looked interesting. I visited `gtfobins.github.io` for finding out the command that can be used for privilege escalation using the SUID permission set on nmap binary file. According to GTFOBins, we can run nmap in interactive mode and execute `bash or sh` binary files. Since nmap binary has SUID permission set, it executes with root privileges and whenever we run command `!sh`, the root shell pops out as the elevated privilege does not get dropped.


![nmap](/assets/img/posts/mr-robot-box-walkthrough/25.webp)

After elevating privileges, I quickly listed out the files located in the root directory and read the contents of `key-3-of-3.txt` which was the final flag.

## 14. What if there was no credentials in the license file?
In such a scenario, I would have waited for the burp suite to figure out the valid username. Also, I could have used hydra for speeding up the process.

```bash
Hydra command for Username Enumerationhydra -L sorted-fsociety.dic -p test 10.10.49.166 http-post-from "/wp-login:log=^USER^&pwd=test&wp-submit=Log+In&redirect_to=https%3A%2F%2F10.10.115.227%2Fwp-admin%2F&testcookie=1:F=Invalid username"
```

In the similar fashion, password can be also brute forced using the hydra using same wordlist. In this way also we could have identified the valid credentials.

#### 14.1 Cracking the raw-md5 password
Here, I have showed how to crack the hashes using crackstation. However, we can use `hashid or hash-identifier` tool for identifying the hash type and cracking it using the hashcat or john the ripper.


## 15. Conclusion
To conclude, I was able to capture all of those three flags. There are multiple tools out there that can be used for achieving the same tasks. One quick suggestion - do not completely depend upon any kind of tool. What really matters is learning the new kind of techniques and building up your own methodology.

Thank you for bearing with me this far. Have good time folks.

!! Happy Learning !!