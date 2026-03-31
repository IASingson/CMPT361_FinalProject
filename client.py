import sys
import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import json

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

    username = input("enter your username: ")

    private_key_file = f"{username}_private.pem"
    public_key_file = f"{username}_public.pem"

    if not (os.path.exists(private_key_file) and os.path.exists(public_key_file)):
        key = RSA.generate(2048)
        with open(private_key_file, 'wb') as f:
            f.write(key.export_key('PEM'))
        with open(public_key_file, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))

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

    if response == b"invalid username or password":
        print("Invalid username or password\nTerminating connection")
        clientSocket.close()
        return
    
    client_private_key = loadPrivateKey(private_key_file)
    # Server will send either a plaintext error message or an RSA-encrypted AES key.
    try:
        # try to decrypt as RSA first
        aes_key = PKCS1_OAEP.new(client_private_key).decrypt(response)
        print("secure connection established")
    except Exception:
        # fallback: else try to decode a text error message
        try:
            text = response.decode()
            if text == "invalid username or password":
                print("Invalid username or password\nTerminating connection")
                clientSocket.close()
                return
            else:
                print("Unexpected server response:", text)
                clientSocket.close()
                return
        except Exception:
            print("Could not process server response")
            clientSocket.close()
            return


    while True:
        print("1) Send Email")
        print("2) List Inbox")
        print("3) Read Email")
        print("4) Exit")

        choice = input("Enter Choice: ").strip()
        encrypted_msg = aesEncrypt(choice, aes_key)
        clientSocket.send(encrypted_msg)

        if choice == "4":
            print("Terminating Connection")
            break
        
        reply = clientSocket.recv(4096)
        decrypted_reply = aesDecrypt(reply, aes_key)

        print("Server: ", decrypted_reply)

        if choice == "1":
            recipients = input("enter recipients: ").strip()
            subject = input("enter the subject: ").strip()[:100]#100 char limit
            body = input("enter the body of email: ").strip()[:10000]#10000 char limit

            email_json = json.dumps({
                "sender": username,
                "recipient": recipients,
                "subject": subject,
                "body": body

            })
    
            clientSocket.send(aesEncrypt(email_json,aes_key))

            confirmation = aesDecrypt(clientSocket.recv(4096), aes_key)
            print("server:", confirmation)

        elif choice == "2":
            try:
                inbox_json = aesDecrypt(clientSocket.recv(4096), aes_key)
                inbox = json.loads(inbox_json)
                if not inbox:
                    print("inbox is empty")
                else:
                    print("inbox:")
                    for email in inbox:
                        print(f"[{email['index']}] From: {email['source']} | Title: {email['title']} |Time: {email['time']}")
                    
            except Exception as e:
                print("Error reading inbox", e)

            clientSocket.send(aesEncrypt("ok",aes_key))
        
        elif choice == "3":
            index = input("enter email index to read: ").strip()
            clientSocket.send(aesEncrypt(index, aes_key))

            content = aesDecrypt(clientSocket.recv(4096), aes_key)
            print("\n===Contents===")
            print(content)
            print("===============")

        else:
            print("invalid choice, choose between 1-4")

    clientSocket.close()
if __name__ == "__main__":
    client()