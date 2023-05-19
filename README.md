# OSCP-tools
scripts and key wordlists used for OSCP/PWK

# How to win - every machine!
1. nmap -p-, -sU, -sV, -A 

   --script vuln

2. Onesixtyone, enum4linux,

   FTP?

3. Nikto, gobuster, curl,
Burp if needed

4. FTP, LFI, SQLi/Union, OR OS Inject

   OR 
   shitty webapp exploit - view pagesource

5. Shell
6. Root
7. Screenshot proof with ifconfig


* * *
# Checklist -
# Network Sweep

```
netdiscover, nbtscan -r ​192.168.1.1-254​, nmap -sn Host Machine
Scan every service port: 
nmap -p-
nmap -sV
nmap -A
nmap -sU -F/--open
nmap -p445 --scriptsafe 

nc -nv 10.11.1.209 666;  interact with strange ports.
```

* * *



'''

#### CHECK FOR EXPLOITS
■ Run ​Searchsploit​ against all enumerated services AND google
```site:exploit-db APP VERSION```
#### Credentials
■ If you find credentials (SMB/SMTP/FTP Traversal), STOP WHAT YOU
ARE DOING!! and re-use on FTP/SSH/Web services. Especially SSH -

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
■ If there is an SMTP service running enumerate for usernames (after checking for exploits)

```perl smtp-user-enum.pl -M VRFY -U names.txt -t 10.1.1.236```
```-> /usr/share/seclists/usernames/Names/names.txt```
