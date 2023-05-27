# OSCP-tools
scripts and key wordlists used for OSCP/PWK

* * *
- [Basic Active Directory](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md)
  -  [Mimikatz](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md#mimikatz)
  -  [Lateral Movement](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md#lateral-movement)
  -  [Advanced Active Directory Reference](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md)
- [Machine Enumeration Checklist](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md)
- [Basic PrivEsc](https://github.com/conma293/OSCP-tools/blob/master/Checklist.md#privilege-escalation---exploits)
  - if you have _SeImpersonatePrivilege_ from ```whoami /privs``` - [Potato/PrintSpoofer](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)
  - [Windows PrivEsc Checklist]
  - [Linux PrivEsc Checklist]
- [oneliners](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/Oneliners.md)
- [tools transfer](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/transfer.md)

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
