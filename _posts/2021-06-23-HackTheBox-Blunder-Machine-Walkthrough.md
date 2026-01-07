---
title: "HackTheBox Blunder Machine Walkthrough"
date: 2021-06-23 00:00:00 +0545
categories: [Red-Team, Labs]
tags: [pentesting, htb, blunder, bludit, cms-exploitation, bruteforce, privilege-escalation, sudo-bypass, cewl, metasploit, hash-cracking]
author: nishant_thakur
description: "Complete walkthrough of HackTheBox Blunder machine. Learn Bludit CMS exploitation, brute force protection bypass, privilege escalation via sudo misconfiguration, and capture user and root flags."
pin: false
math: false
mermaid: false
---


### 1. Overview

Hello everyone, hope you guys are doing well. In this blog post, I will provide walk-though of Blunder Machine from Hack The Box. Hack the Box is an online platform that allows us to test out penetration testing skills and exchange ideas and methodologies with thousands of people in the security field. It comprises of active and retired machines that can be accessed via our own PC using OpenVPN.
Press enter or click to view image in full size

![HTB Screenshot](/assets/img/posts/hackthebox-blunder-machine-walkthrough/0_htb.png)


Without any delay let’s head toward the detailed explanation about each steps that was carried out while gaining the user and root flag of Blunder machine. Let us begin the scanning and enumeration process.


### 2. Executing Nmap Scan
A quick nmap scan was launched against the Blunder Machine by executing the command “nmap -sC -sV -oA nmap/blunder 10.10.10.191”. Only one port 80 (http) was found to be in open state.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/1_nmap.webp)
_Nmap scan report of Blunder Machine_


### 3. Web Enumeration
After analyzing the result of Nmap scan, it can be concluded that the only option available for us to perform further enumeration is via TCP Port 80. The corresponding web page was accessed via web browser.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/2.png)


### 4. Executing Dirbuster
Before manually poking around the web content, it’s always good to have some enumeration running in the background. Thus, Dirbuster-GUI was launched using the wordlist “/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt” and it quickly identified admin directory.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/3.webp)

Meanwhile, Dirbuster also shows the same result in terminal as well.


![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/4.webp)

Before accessing this web directory, manual enumeration of the website was carried out and nothing interesting was identified.

### 5. Accessing the web directory
The admin directory displayed a login page with the title of BLUDIT which is a CMS (Content Management System).

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/5.webp)


### 6. Trying Random Credentials
Immediately, I tried some common credentials such as admin:admin, admin:password, user:password and so on. Also I looked for default credentials of Bludit CMS in the internet. None of these worked.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/6.webp)

### 7. Viewing Page Source

After analyzing the source of login page, it was found that the web application was using Bludit version 3.9.2.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/7.webp)


### 8. Executing Searchsploit
As CMS version was identified, it was time to look for corresponding exploit. Searchsploit was launched by executing the command “searchspoit bludit”. It showed multiple exploit. However, there exploit would work only for authenticated users.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/8.webp)

### 9. Initiating wfuzz scanning
For executing those exploits it is necessary to have valid credentials and further enumeration was carried out using wfuzz tool which revealed two interesting files namely robots.txt and todo.txt.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/9.webp)
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/10.webp)
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/11.webp)

Nothing interesting was identified in robots.txt file. However, potential username (fergus) was found in todo.txt file.

### 10. Brute Force Protection Bypass
Before brute-forcing password, I read the Bludit documentation which clearly stated that, users IP Address gets blocked after 10 invalid login attempts.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/12.webp)

Bludit CMS Version 3.9.2 adds IP Address of the visitor to the **X-Forwarded-For** header tag for each login requests made to the web server and using this method it keeps count of requests that the particular user made to the web application. Based on that count value, users are either allowed or blocked from login in to Bludit based applications. Although everything looks fine, there lies a small flaw in the program i.e. X-Forwarded-For tag is unsanitized meaning that anybody can temper its value, which provides surface area for launching Brute Force attack. Anyone can write a simple python script that renders the value of X-Forwarded-For to new IP Address on each subsequent request bypassing the Brute Force protection provided by Bludit CMS 3.9.2. Therefore, I downloaded script from [GitHub](https://github.com/musyoka101/Bludit-CMS-Version-3.9.2-Brute-Force-Protection-Bypass-script/tree/master) to guess a possible password for user Fergus.


### 11. Using CeWL
We can try to brute-force using wordlist such as rockyou.txt. However, it may take long time. Before using rockyou.txt, I decided to create a wordlist using the contents of home page of the web application. After doing some research, I found out about a tool namely cewl. This tool would spider the provided URL and scrap words that has certain length as specified by user.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/13.webp)
_Executing cewl tool to generate password_

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/14.webp)
_Total 306 possible password collected_


### 12. Launching Brute Force Attack
The script namely bruteforce.py that was downloaded previously was used for accomplishing the task. Argument such as IP Address (10.10.10.191), username (fergus) and password list (passwords.txt) was supplied to the script.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/15.webp)
_Launching brute force attack_
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/16.webp)
_Valid credentials found_

After certain attempt valid credential **(fergus:RolandDeschain)** was identified.

### 13. Logging into the Web Application
The credential worked and we were redirected to the dashboard of the web application.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/17.webp)
_Using the obtained credentials to login_
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/18.webp)
_Dashboard of the application_

### 14. Exploitation
Now that we are authenticated, its time to launch the directory traversal exploit as shown by the searchsploit result. For this demonstration, we are using metasploit-framework. However, we can also perform the same exploitation manually.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/19.webp)
_searching for bludit in metasploit-framework_

A command **search bludit** was executed and it showed one exploit module. The module was loaded and available options were listed out.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/20.webp)
_Loading the exploit module_

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/21.webp)
_Listing out available options_

As we have already gathered values for these parameters, all the values were set accordingly using the set command. The value of RPORT was already set to 80 by default. The values that were set are **BLUDITUSER: fergus, BLUDITPASS: RolandDeschain, RHOST: 10.10.10.191, LHOST: 10.10.14.136, and LPORT: 4444.**

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/22.webp)
_Setting up all the parameters accordingly_

After running the exploit command, meterpreter session was opened as shown below.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/23.webp)
_Meterpreter session opened with Blunder Machine_

### 15. Post Exploitation
After looking around, it was found that two different version of bludit was located in the **/var/www/** directory. On further enumerating, username and password hash was found in **users.php** file.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/24.webp)
_Two different versions of bludit_

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/25.webp)
_Username and password hash found in users.php file_


### 16. Hash Identification
The hash type was identified to be SHA-1 using the tool namely **hash-id.py**.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/26.webp)
_Identifying Hash Type_

### 17. Cracking the Hash
There are tools such as hashcat, John the Ripper and various online tools for decoding various hash types. The hash was decoded and plain text password was identified to be **Password120**.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/27.webp)
_Decoding the hash value_

### 18. Switching user to Hugo
The command “su hugo” was executed and corresponding password (Password120) was supplied. The user was successfully switched to hugo.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/28.webp)
_Switching user to hugo_

### 19. Obtaining User Flag
The users flag was located in the hugo’s home directory.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/29.webp)
_User Flag_

### 20. Obtaining Root Flag
As I had the credential for hugo user, the first thing that I could do to obtain the root flag would be checking for command that hugo user is allowed to run with sudo permission. The command `sudo -l` was executed.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/30.webp)
_Checking sudo permission for hugo user_

The result showed that hugo user can run `/bin/bash` as any user but not as a root user. But after some research, it was found that we can bypass this permission check and run /bin/bash as root user.

![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/31.webp)
_Running bash with root permission_

After executing the command `sudo -u#-1 /bin/bash`, user was switched from hugo to root, which was further identified by `id` command.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/32.webp)
_Escalating privilege using bash_

The root flag was located in the root user’s home directory.
![Nmap Scan](/assets/img/posts/hackthebox-blunder-machine-walkthrough/33.webp)
_Gaining the root flag_

### 21. Conclusion
In this way, both user flag and root flag on the Blunder machine were captured. Thank you for bearing with me this far. Have good time folks.

!! Happy Hacking !!