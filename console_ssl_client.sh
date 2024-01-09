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
