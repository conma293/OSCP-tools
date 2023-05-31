# OSCP-tools
scripts and key wordlists used for OSCP/PWK

* * *
- [Basic Active Directory Attacks](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md)
  -  [Mimikatz](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md#mimikatz)
  -  [Lateral Movement](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md#lateral-movement)
- [Machine Enumeration Checklist](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md)
- [Basic PrivEsc](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#privilege-escalation---exploits)
  - if you have _SeImpersonatePrivilege_ from ```whoami /privs``` - use [Potato/PrintSpoofer](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)
  - [Windows PrivEsc Checklist](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#priv-esc-windows-check-list)
  - [Linux PrivEsc Checklist](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#priv-esc-linux-check-list)
- [one-liners](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/Oneliners.md)
- [Tools Transfer](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/transfer.md)

[Advanced Active Directory Reference](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md)

* * *

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

# Other cheatsheets
https://github.com/0xsyr0/OSCP
