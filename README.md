# smtp_smuggling_checker.py
smtp smuggling testing tool

### Infos:
https://www.postfix.org/smtp-smuggling.html

and here:

https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/

### Beware this is alpha POC !! tested with postfix and python3

### How to run:

```python
.\smtp_smuggling_checker.py --server mail.server.com --port 587 --user user@server.com --rcpt vic@server.com --mode def
```

