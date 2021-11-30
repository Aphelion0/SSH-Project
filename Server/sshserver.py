from Crypto.PublicKey import RSA
import socket
import argparse

import os
import sys
import time
import random
import string
import base64
import shutil

import hashlib
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES, PKCS1_OAEP

if __name__ == '__main__':
    assert(len(sys.argv) == 2)
    port = int(sys.argv[1])

    if(port == 0):
        print("User Registration Mode")
        print("Keep Entering username and passphrase")
        print("Enter * to terminate")
        while(True):
            x = input()
            if(x == "*"):
                break
            username = x
            passphrase = input()
            b_passphrase = bytes(passphrase,'utf-8')
            iv_salt = os.urandom(16)
            #print(iv_salt)
            zeros = "0"*16
            b_zeros = bytes(zeros,'utf-8')
            cipher = AES.new(b_passphrase, AES.MODE_CBC, iv_salt)
            msg =cipher.encrypt(b_zeros)
            base64_iv = base64.b64encode(iv_salt)
            base64_msg = base64.b64encode(msg)
            str_iv = base64_iv.decode('utf-8')
            str_msg = base64_msg.decode('utf-8')
            with open('UserCredentials/'+username+".txt",'w') as f:
                f.write(username)
                f.write("\n")
                f.write(str_msg)
                f.write("\n")
                f.write(str_iv)
                f.close()
            
    else:
        print('Server Running @ port',port)

        #Step1 : Server Generates RSA Keys and saves to files serverpub.txt serverpriv.txt.
        #GENERATION
        Server_key = RSA.generate(1024)
        Server_public_key = Server_key.exportKey('PEM')
        Server_private_key = Server_key.publickey().exportKey('PEM')
        #SAVE PUBLIC KEY
        with open('serverkeys/serverpub.txt','wb') as f:
            f.write(Server_public_key)
            f.close()
        #SAVE PRIVATE KEY
        with open('serverkeys/serverpriv.txt','wb') as f:
            f.write(Server_private_key)
            f.close()    

        print("SSH Server Running")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('127.0.0.1', port)
        sock.bind(server_address)
        sock.listen(15)

        while True:
            close_conn = False
            connection, client_address = sock.accept()
            print("Initiate Session")
            try:
                data = connection.recv(1024)
                username = data.decode('utf-8')
                with open('serverkeys/serverpub.txt','rb') as f:
                    x = f.read()
                print('Sending Public Key')
                connection.sendall(x)
            finally:
                print("Awaiting Session Key")
            
            try:
                data = connection.recv(1024)
                with open('serverkeys/serverpub.txt','rb') as f:
                    b_x = f.read()
                x = b_x.decode('utf-8')
                key = RSA.importKey(b_x)
                cipher_rsa = PKCS1_OAEP.new(key)
                decr = cipher_rsa.decrypt(data)
                arguments = decr.split(b'|')
                user_name = arguments[0].decode('utf-8')
                b_pass_phrase = arguments[1]
                session_key = arguments[2].decode('utf-8')

                with open('UserCredentials/'+username+'.txt') as f:
                    user,base64_paswd,base64_iv_val = f.read().split('\n')

                bin_iv = bytes(base64_iv_val,'utf-8')
                actual_iv = base64.b64decode(bin_iv)
    
                iv_salt = actual_iv

                zeros = "0"*16
                b_zeros = bytes(zeros,'utf-8')
                cipher = AES.new(b_pass_phrase, AES.MODE_CBC, iv_salt)
                msg =cipher.encrypt(b_zeros)
                base64_msg_check = base64.b64encode(msg)

                if(base64_msg_check == bytes(base64_paswd,'utf-8')):
                    print("AUTHENTOCATION SUCCESSFUL")
                    print('Proceeding with Session Key : ',session_key)
                    connection.sendall(bytes('OK','utf-8'))
                else:
                    print("AUTHENTICATION FAILED")
                    print("SERVER RESET")
                    connection.sendall(bytes('NOK','utf-8'))
                    close_conn = True
                #Check passphrase
            finally:
                if(close_conn):
                    sock.close()
                    connection.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    time.sleep(10)
                    continue

            print(session_key)
            cipher = AES.new(session_key, AES.MODE_ECB)

            path = []

            while True:
                print("SSH Server in Session: Awaiting instructions")
                try:
                    data = connection.recv(1024)
                    print(data)
                    plaintext = cipher.decrypt(data).decode('utf-8')
                    cmd = plaintext.split('|')[0]
                    cmds = cmd.split(' ')
                    frc = cmds[0]
                    cmdlen = len(cmds)
                    ok = True
                    if(frc == "listfiles" and cmdlen == 1):
                        os.system('ls >out.txt')
                    elif(frc == "pwd" and cmdlen == 1):
                        os.system('pwd > out.txt')
                    elif(frc == "chgdir" and cmdlen == 2):
                        os.chdir(cmds[1])
                    elif(frc == "cp" and cmdlen == 4):
                        source_folder = ''
                        if ( len(cmds[2])>0 ):
                            source_folder = cmds[2] + "/"
                        source_folder = source_folder + cmds[1]
                        dest_folder = ''
                        if ( len(cmds[3])>0 ):
                            dest_folder = cmds[3] + "/"
                        dest_folder = dest_folder + cmds[1]
                        os.system('cp '+ source_folder +' ' + dest_folder + ' > out.txt')
                    elif(frc == "mv" and cmdlen == 4):
                        source_folder = ''
                        if( len(cmds[2])>0 ):
                            source_folder = cmds[2] + "/"
                        source_folder = source_folder + cmds[1]
                        dest_folder = ''
                        if( len(cmds[3])>0 ):
                            dest_folder = cmds[3] + "/"
                        dest_folder = dest_folder + cmds[1]
                        os.system('mv '+ source_folder +' ' + dest_folder + ' > out.txt')
                    elif(frc == 'logout'):
                        connection.sendall(bytes('OK','utf-8'))
                        connection.close()
                        break
                    else:
                        ok = False
                
                    data = ''
                    try:
                        f = open("out.txt",'r')
                        data = f.read()
                        #f.write('')
                    except IOError:
                        #print('OOPS')
                        data = 'OK'
                    finally:
                        f.close()
                    
                    if(ok==False):
                        data = 'NOK'

                    rem = 16 - len(data)%16
                    data = data + "|"*rem
                    #print(data)
                    cipher_text = cipher.encrypt(data)
                    connection.sendall(cipher_text)
                finally:
                    print("Finished Command Execution")