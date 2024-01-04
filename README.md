# smtp_smuggling_checker.py
smtp smuggling testing tool with tls / starttls support

### Infos:
https://www.postfix.org/smtp-smuggling.html

and here:

https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/

### Beware this is alpha POC !! tested with postfix and python3

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
  --mode MODE      Rawmode or Default?
```

### Run like this:

```python
.\smtp_smuggling_checker.py --server mail.server.com --port 587 --user user@server.com --rcpt vic@server.com --mode def
```

