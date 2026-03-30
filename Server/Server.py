# TODO: 
# - Remove debug prints
# - Add more comments to code
# - Remove Threading mode and related code (Using for Test purposes on Windows)
# - Remove `import threading`

import socket
import json 
import os
import datetime
import glob
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

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
    
def server():
    # Helpers for AES ECB I/O compatible with provided client
    def pad(msg: str) -> str:
        while len(msg) % 16 != 0:
            msg += " "
        return msg

    def encrypt_aes(sym_key: bytes, plaintext: str) -> bytes:
        cipher = AES.new(sym_key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext).encode())

    def decrypt_aes(sym_key: bytes, payload: bytes) -> str:
        if not payload:
            return None
        cipher = AES.new(sym_key, AES.MODE_ECB)
        return cipher.decrypt(payload).decode().rstrip()

    def send_encrypted(sock, sym_key: bytes, plaintext: str):
        try:
            sock.send(encrypt_aes(sym_key, plaintext))
        except Exception:
            pass

    def recv_encrypted(sock, sym_key: bytes):
        try:
            payload = sock.recv(4096)
        except Exception:
            return None
        if not payload:
            return None
        return decrypt_aes(sym_key, payload)

    # Base directory of this server script (where server keys live)
    base_dir = os.path.abspath(os.path.dirname(__file__))

    # Create server Public and Private Keys inside the server directory if they don't exist
    server_priv_path = os.path.join(base_dir, 'server_private.pem')
    server_pub_path = os.path.join(base_dir, 'server_public.pem')
    if not (os.path.exists(server_priv_path) and os.path.exists(server_pub_path)):
        key = RSA.generate(2048)
        with open(server_priv_path, 'wb') as f:
            f.write(key.export_key('PEM'))
        with open(server_pub_path, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow quick reuse of the address when restarting the server
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_host = "localhost"
    server_port = 13000

    server_socket.bind((server_host, server_port))

    # Listen for a max of 5 incoming connections
    server_socket.listen(5)

    # --------------------------------------------------------------------------------
    # Enable threading mode for testing on Windows (since fork() is not available)
    use_threading = True
    # use_threading = False
    if use_threading:
        print("Debug: USE_THREADING is on. Server will use threads instead of fork()")
    # --------------------------------------------------------------------------------

    # Accept loop: fork when available, otherwise handle single
    def handle_client(client_socket, client_addr):
        print(f"Debug: Connection from {client_addr}")
        try:
            # Receive credentials encrypted with server public key (client sends raw RSA ciphertext)
            enc_credentials = client_socket.recv(4096)
            print(f"Debug: Received encrypted credentials ({len(enc_credentials)} bytes)")
            if not enc_credentials:
                client_socket.close()
                if hasattr(os, 'fork'):
                    os._exit(0)
                return

            # Decrypt with server private key (from server directory)
            try:
                with open(server_priv_path, 'rb') as f:
                    private = RSA.import_key(f.read())
            except Exception:
                client_socket.send(b"Server private key not available")
                client_socket.close()
                print("Debug: server_private.pem missing or unreadable")
                if hasattr(os, 'fork'):
                    os._exit(0)
                return
            rsa_cipher = PKCS1_OAEP.new(private)
            try:
                credentials_bytes = rsa_cipher.decrypt(enc_credentials)
            except Exception:
                client_socket.send(b"Invalid credential encryption")
                client_socket.close()
                print("Debug: Failed to decrypt credentials")
                if hasattr(os, 'fork'):
                    os._exit(0)
                return

            # Receives credentials in "<username> <password>" format 
            try:
                cred_text = credentials_bytes.decode()
                username, password = cred_text.split(' ', 1)
                print(f"Debug: Received credentials for username: {username}")
            except Exception:
                client_socket.send(b"Invalid credential format")
                client_socket.close()
                print("Debug: Failed to parse credentials")
                if hasattr(os, 'fork'):
                    os._exit(0)
                return

            # Check if username and password match the ones in user_pass.json
            users_file = os.path.join(base_dir, 'user_pass.json')
            with open(users_file, 'r') as f:
                users = json.load(f)
                user = next((u for u in users if u['username'] == username and u['password'] == password), None)
                if user:
                    # Generate sym_key and send to client encrypted with client's public key
                    sym_key = get_random_bytes(32)
                    client_public_key_path = os.path.join(base_dir, f"{username}_public.pem")
                    if not os.path.exists(client_public_key_path):
                        client_socket.send(b"Client public key not found on server")
                        client_socket.close()
                        print(f"Debug: Public key for {username} not found. Connection terminated.")
                        if hasattr(os, 'fork'):
                            os._exit(0)
                        return
                    with open(client_public_key_path, 'rb') as f:
                        client_public_key = RSA.import_key(f.read())
                    rsa_enc = PKCS1_OAEP.new(client_public_key)
                    enc_sym = rsa_enc.encrypt(sym_key)
                    # Send RSA-encrypted sym_key to client
                    client_socket.send(enc_sym)
                    print(f"Connection Accepted and Symmetric Key Generated for client: {username}")
                else:
                    # Send error message as plaintext, print to server, and terminate connection
                    client_socket.send(b"invalid username or password")
                    print(f"The received client information: {username} is invalid (Connection Terminated).")
                    client_socket.close()
                    if hasattr(os, 'fork'):
                        os._exit(0)
                    return

            # After Authentication, loop menu options until client terminates connection
            while True:
                # Receive client's encrypted message
                client_choice = recv_encrypted(client_socket, sym_key)

                if client_choice == "1": # Sending email subprotocol
                    # Ask client to send the email (encrypted with sym_key)
                    send_encrypted(client_socket, sym_key, "Send the email")
                    email_json = recv_encrypted(client_socket, sym_key)
                    if email_json is None:
                        send_encrypted(client_socket, sym_key, "Failed to receive email")
                        continue
                    try:
                        email_obj = json.loads(email_json)
                        sender = email_obj.get('sender')
                        destinations = email_obj.get('recipient')
                        title = email_obj.get('subject')
                        body = email_obj.get('body')
                    except Exception:
                        send_encrypted(client_socket, sym_key, "Invalid email format")
                        continue

                    if title is None or len(title) > 100:
                        send_encrypted(client_socket, sym_key, "Invalid title length")
                        continue
                    if body is None or len(body) > 1000000:
                        send_encrypted(client_socket, sym_key, "Invalid content length")
                        continue

                    timestamp = datetime.datetime.now().isoformat()
                    recipients = [r.strip() for r in destinations.split(';') if r.strip()]
                    print(f"An email from {sender} is sent to {recipients} has a content length of {len(body)}")

                    # Save email into each recipient inbox
                    for r in recipients:
                        inbox_dir = os.path.join(base_dir, r)
                        os.makedirs(inbox_dir, exist_ok=True)
                        # sanitize title for filename
                        safe_title = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in title).strip()
                        filename = f"{sender}_{safe_title}.txt"
                        filepath = os.path.join(inbox_dir, filename)
                        with open(filepath, 'w', encoding='utf-8') as email:
                            email.write(f"From: {sender}\n")
                            email.write(f"To: {';'.join(recipients)}\n")
                            email.write(f"Time and Date: {timestamp}\n")
                            email.write(f"Title: {title}\n")
                            email.write(f"Content Length: {len(body)}\n")
                            email.write(f"Content: {body}\n")

                    send_encrypted(client_socket, sym_key, "OK")

                elif client_choice == "2": # Viewing inbox subprotocol
                    # Gather list of emails for this user
                    inbox_dir = os.path.join(base_dir, username)
                    os.makedirs(inbox_dir, exist_ok=True)
                    files = glob.glob(os.path.join(inbox_dir, '*.txt'))
                    # Sort by modified time
                    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                    out = []
                    # Currently assumes that source username and titles dont contain any underscores
                    for i, fpath in enumerate(files, start=1):
                        # Use filename format {source_username}_{title}.txt to extract source and title
                        base = os.path.splitext(os.path.basename(fpath))[0]
                        if '_' in base:
                            src, title_part = base.split('_', 1)
                        else:
                            src, title_part = base, base
                        title = title_part.replace('_', ' ')
                        time = datetime.datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat()
                        out.append({'index': i, 'source': src, 'time': time, 'title': title})
                    send_encrypted(client_socket, sym_key, json.dumps(out))
                    # Wait for `OK` from client
                    _ = recv_encrypted(client_socket, sym_key)

                elif client_choice == "3": # Viewing email subprotocol
                    send_encrypted(client_socket, sym_key, "the server request email index")
                    index_str = recv_encrypted(client_socket, sym_key)
                    try:
                        index = int(index_str)
                    except Exception:
                        send_encrypted(client_socket, sym_key, "Invalid index")
                        continue
                    inbox_dir = os.path.join(base_dir, username)
                    files = glob.glob(os.path.join(inbox_dir, '*.txt'))
                    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                    if index < 1 or index > len(files):
                        send_encrypted(client_socket, sym_key, "Index out of range")
                        continue
                    with open(files[index-1], 'r', encoding='utf-8') as rf:
                        content = rf.read()
                    send_encrypted(client_socket, sym_key, content)

                else: # Terminate connection subprotocol
                    client_socket.close()
                    print(f"Terminating connection with {username}")
                    break
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            if hasattr(os, 'fork'):
                os._exit(0)
            return

    # Main accept new client connection loop
    while True:
        # Wait for a new client connection
        client_socket, client_addr = server_socket.accept()

        # Prefer fork() unless `use_threading` is True; fall back to threads
        # TODO: Remove all threading code and just use fork() as Assignment Requirements
        if (not use_threading) and hasattr(os, 'fork'):
            pid = os.fork()
            if pid == 0:
                # Child process
                server_socket.close()
                handle_client(client_socket, client_addr)
                # should never reach here
                os._exit(0)
            else:
                # Parent process
                try:
                    client_socket.close()
                except Exception:
                    pass
                # Continue accepting
                continue
        else:
            # Use threads for concurrency
            try:
                t = threading.Thread(target=handle_client, args=(client_socket, client_addr), daemon=True)
                t.start()
            except Exception:
                # Fallback to sequential handling if thread creation fails
                handle_client(client_socket, client_addr)
            # Continue accepting next client
            continue


if __name__ == "__main__":
    server()