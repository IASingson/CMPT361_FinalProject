# TODO remove unneeded comments, add more detailed comments
import sys
import socket
import os
import hashlib
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

def hash_password(password, salt=b'static_salt_for_demo'):
    """Hash password using PBKDF2 with SHA-256"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

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

    password = input("enter your password: ")


    serverName = input("Enter the server IP or Name: ")
    serverPort = 13000
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((serverName, serverPort))
    except Exception as e: 
        print("connection error:", e)
        return
    
    #---------------------------------------

    hashed_password = hash_password(password)

    server_public_key = loadPublicKey("server_public.pem")

    encryptedCredentials = rsa_encrypt(username + " " + hashed_password, server_public_key)
    clientSocket.send(encryptedCredentials)

    response = clientSocket.recv(4096)

    try:
        client_private_key = loadPrivateKey(f"{username}_private.pem")
    except Exception:
        clientSocket.close()
        print("Invalid username or password\nTerminating connection")
        return
    
    # Server will send either a plaintext error message or an RSA-encrypted AES key.
    try:
        # try to decrypt as RSA first
        aes_key = PKCS1_OAEP.new(client_private_key).decrypt(response)
        clientSocket.send(aesEncrypt("OK",aes_key))
        print("Secure Connection Established")
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

    # Receive display menu from server
    menuMsg = aesDecrypt(clientSocket.recv(4096), aes_key)

    while True:
        # Display the menu get take user choice
        choice = input(menuMsg).strip()
        encrypted_msg = aesEncrypt(choice, aes_key)
        clientSocket.send(encrypted_msg)
    #if choice is 4, we break the loop and close the connection. Otherwise, we handle the other choices as follows:
        if choice == "4":
            print("Terminating Connection")
            break
    #if choice is 1, we prompt the user for email details and format in json then sends to sercer encrypted
        if choice == "1":
            subprotocol_request = aesDecrypt(clientSocket.recv(1024), aes_key)
            recipients = input("Enter recipients (separated by ;):").strip()
            subject = input("Enter title: ").strip()[:100]#100 char limit
            
            # Ask user if they want to fill email body from file or console input
            load_body_from_file = input("Would you like to load contents from a file?(Y/N): ")
            if load_body_from_file.strip().upper() == 'Y':
                filename = input("Enter filename: ")
                try:
                    with open(filename, 'r') as f:
                        body = f.read()[:10000]  # 10000 char limit
                except Exception as e:
                    print("Error reading file:", e)
                    body = ""
            else:
                body = input("Enter the body of email: ").strip()[:10000]#10000 char limit

            email_json = json.dumps({
                "sender": username,
                "recipient": recipients,
                "subject": subject,
                "body": body
            })
    
            clientSocket.send(aesEncrypt(email_json,aes_key))

            confirmation = aesDecrypt(clientSocket.recv(4096), aes_key)
            print("The message is sent to the server.", confirmation)
        #if choice is 2, request inbox from server and display
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
                    
            except json.JSONDecodeError:
                print("error: failed to decode inbox JSON")
            except Exception as e:
                print("Error reading inbox", e)

            clientSocket.send(aesEncrypt("OK",aes_key))
        #if choice is 3, prompts user for index and display content
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