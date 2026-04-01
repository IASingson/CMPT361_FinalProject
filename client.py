# TODO remove unneeded comments, add more detailed comments
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

        if choice == "4":
            print("Terminating Connection")
            break

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

        elif choice == "2":
            try:
                inbox_json = aesDecrypt(clientSocket.recv(4096), aes_key)
                inbox = json.loads(inbox_json)
                if not inbox:
                    print("Inbox is empty")
                else:
                    print(f"{'Index':<6} {'From':<15} {'DateTime':<26} {'Title':<100}")
                    for email in inbox:
                        print(f"{str(email['index']):<6} {email['source']:<15} {email['time']:<26} {email['title']:<100}")
                    
            except json.JSONDecodeError:
                print("error: failed to decode inbox JSON")
            except Exception as e:
                print("Error reading inbox", e)

            clientSocket.send(aesEncrypt("OK",aes_key))
        
        elif choice == "3":
            index = input("Enter the email index you wish to view: ").strip()
            clientSocket.send(aesEncrypt(index, aes_key))

            subprotocol_request = aesDecrypt(clientSocket.recv(1024), aes_key)
            content = aesDecrypt(clientSocket.recv(4096), aes_key)
            print("\n" + content + "\n")

        else:
            print("invalid choice, choose between 1-4")

    clientSocket.close()
if __name__ == "__main__":
    client()