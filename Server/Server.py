import socket
import json 
import os
import datetime

menuMsg = "Select the operation:\n\t1) Create and send an Email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection \n\nChoice: "

# Email Format:
# From: [source client username] \n
# To: [list of destination client usernames separated by ;] \n
# Time and Date: [timestamp when email was received]\n
# Title: [subject of email (with 100 character limit)] \n
# Content Length: [numbers of characters in content] \n
# Content: [body of email (with 1,000,000 character limit)]1
class Email:
    def __init__(self, sender, recipient, subject, body, subject_length):
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.body = body
        self.subject_length = subject_length
        self.timestamp = datetime.datetime.now().isoformat()

    def to_dict(self):
        return {
            'source': self.sender,
            'destination': self.recipient,
            'title': self.subject,
            'content': self.body,
            'subject_length': self.subject_length,
            'timestamp': self.timestamp
        }
    
def main():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_host = "localhost"
    server_port = 13000

    server_socket.bind((server_host, server_port))
    # Listen for a max of 5 incoming connections
    server_socket.listen(5)


    client_socket, _ = server_socket.accept()


    # Receive username and password from client encrypted with server public key (server_public.pem)
    credentials = client_socket.recv(1024).decode()
    credentials = json.loads(credentials)
    username = credentials['username']
    password = credentials['password']
    # Check if username and password match the ones in user_pass.json
    with open('user_pass.json', 'r') as f:
        users = json.load(f)
        user = next((u for u in users if u['username'] == username and u['password'] == password), None)
        if user:
            # TODO: generate `sym_key`(256 AES key), and send to client with corresponding **client public key**

            # client_socket.send("".encode())
            print(f"Connection Accepted and Symmetric Key Generated for client: {username}")
        else:
            client_socket.send("Invalid username or password".encode())
            print(f"The received client information: {username} is invalid (Connection Terminated).")
            client_socket.close()
            return
    
    # After Authentication, loop menu options until client terminates connection
    while True:
        # Send menu options to client
        client_socket.send(menuMsg.encode())
        # Receive client's choice

        client_choice = client_socket.recv(1024).decode()

        if client_choice == "1": # Sending email subprotocol 
            #
        elif client_choice == "2": # Viewing inbox subprotocol
            #
        elif client_choice == "3": # Viewing email subprotocol
            #
        else: # Terminate connection subprotocol
            client_socket.close()
            print(f"Terminating connection with {username}")
            break


if __name__ == "__main__":
    main()