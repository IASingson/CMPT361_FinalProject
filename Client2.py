import json
import socket
import os
import datetime
import sys

FORMAT = 'ascii'
SIZE = 2048

def client():
    # server information
    server_name = 'localhost'
    server_port = 13000

    # create client socket that uses IPv4 and TCP protocols
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation', e)
        sys.exit(1)

    try:
        # client connects to the server
        client_socket.connect((server_name, server_port))

        # ask the client user for username and password 
        client_username = input('Enter your username: ')
        client_password = input ('Enter password: ')

        # encrypt username and password with the server's public key

        # send client's encrypted username and password to server 

        # if client user inputs wrong username and password
        from_server = client_socket.recv(FORMAT).decode(SIZE)
        if from_server == 'Invalid username or password':
            print(from_server + '\nTerminating')
            client_socket.close()

        # otherwise decrypt message
        else:
            sym_key = client_socket.recv(FORMAT).decode(SIZE)
            sym_key += 'Ok'

        # ask client for user menu choice
        from_server = client_socket.recv(FORMAT).decode(SIZE)
        to_server = input(from_server).encode(FORMAT)

        # stay in loop while client choice is not 4) terminate the connection
        while to_server != '4':

            # if client choice is 1, perform sending email subprotocol
            if to_server == '1':
                # decrypt server message 

                # ask client user to enter destination email usernames and email title 

                # ask user to enter message through terminal or get message from existing text file

                # create the email message according to section D 

                # encrypt using the sym_key and send to server side

                # print confirmation message to client user

                print("The message is sent to the server.")
                pass

            # if client choice is 2, perform viewing inbox subprotocol
            if to_server == '2':
                

            # if client choice is 3, perform viewing email subprotocol

        
                pass
        



    except socket.error as e:
        print('An error occurred:', e)
        client_socket.close()
        sys.exit(1)

#------------------------------------------------------------------
client()
    

    
    
