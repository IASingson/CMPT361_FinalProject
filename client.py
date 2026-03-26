import sys
import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def loadPublicKey(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())
    
def loadPrivateKey(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())
    
def rsa_encrypt(message, publicKey):
    cipher = PKCS1_OAEP.new(publicKey)
    return cipher.encrypt(message.encode())

def rsa_decypt(message, privateKey):
    cipher = PKCS1_OAEP.new(privateKey)
    return cipher.decrypt(message)

def pad(msg):
    while len(msg) % 16 != 0:
        msg += " "
    return msg

def aesEncrypt(msg, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(msg).encode())

def aesDecrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext).decode().strip()





def client():
    serverName = input("Enter the server IP or Name: ")
    serverPort = 13000
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((serverName, serverPort))
    except Exception as e: 
        print("connection error:", e)
        return
    
    #---------------------------------------

    username = input("enter your username: ")
    password = input("enter your password: ")

    server_public_key = loadPublicKey("server_public.pem")

    encryptedCredentials = rsa_encrypt(username + " " + password, server_public_key)
    clientSocket.send(encryptedCredentials)

    response = clientSocket.recv(4096)

    if response.decode() == "invalid username or password":
        print("Invalid username or password\nTerminating connection")
        clientSocket.close()
        return
    
    client_private_key = loadPrivateKey("client_private.pem")

    encrypted_aes_key = clientSocket.recv(4096)
    aes_key = PKCS1_OAEP.new(client_private_key).decrypt(encrypted_aes_key)

    print("secure connection established")


    while True:
        msg = input("enter message or exit: ")
        
        if msg.lower() == "exit":
            break
        encrypted_msg = aesEncrypt(msg, aes_key)
        clientSocket.send(encrypted_msg)

        reply = clientSocket.recv(4096)
        decrypted_reply = easDecrypt(reply, aes_key)

        print("Server: ", decrypted_reply)
    
    clientSocket.close()

if __name__ == "__main__":
    client()