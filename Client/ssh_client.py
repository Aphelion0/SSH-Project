from Crypto.PublicKey import RSA
import socket
import argparse

import os
import sys
import time
import random
import string
import base64

import hashlib
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES, PKCS1_OAEP

if __name__ == '__main__':
    ssh_ip = "127.0.0.1"
    port = -1
    user = ""
    while(True):
        print("$",end=" ")
        arg = input()
        args = arg.split(' ')
        if(len(args) == 5):
            ssh_ip = args[1]
            port = int(args[2])
            user = args[3]
        else:
            port = int(args[1])
            user = args[2]
        
        passphrase = input()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ssh_ip, port)
        sock.connect(server_address)
        print("Connected to SSH Server")
        try:
            hello_message = bytes(user,'utf-8')
            sock.sendall(hello_message)
            b_data = sock.recv(1024)
            #print("Received public key : ",b_data)
            data = b_data.decode('utf-8')
            key = RSA.importKey(data)
            cipher_rsa = PKCS1_OAEP.new(key)
        finally:
            print("Received Public Key.")
        
        try:
            res = ''.join(random.choices(string.ascii_uppercase +string.digits, k = 32))
            msg = bytes(user+'|' + passphrase + '|'+res,'utf-8')
            rem = 16 - len(msg)%16
            msg = msg + bytes("|"*rem,'utf-8')
            ciphertext = cipher_rsa.encrypt(msg)
            plaintext = cipher_rsa.decrypt(ciphertext)
            print(plaintext)
            sock.sendall(ciphertext)
            b_data = sock.recv(1024)
            data = b_data.decode('utf-8')
            if(data == "NOK"):
                print("AUTHENTICATION FAILED")
                continue
            else:
                print("AUTHENTICATION SUCCESFUL")
        finally:
            print("Send Encrypted Session Key")

        while(True):
            print("SSH>",end=" ")
            try:
                commands = input()
                command_msg = bytes(commands,'utf-8')
                cipher = AES.new(res, AES.MODE_ECB)
                rem = 16 - len(command_msg)%16
                command_msg = command_msg + bytes("|"*rem,'utf-8')
                cipher_text = cipher.encrypt(command_msg)
                #print(commands)
                #print(cipher_text)
                sock.sendall(cipher_text)
                b_data = sock.recv(1024)
                if(commands == "logout"):
                    break
                dt = cipher.decrypt(b_data).decode('utf-8')
                #print(dt)
                print(dt.split('|')[0])
            finally:
                pass