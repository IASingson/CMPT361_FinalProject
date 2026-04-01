# Key Generator for all keys used in project

import json
import os
from Crypto.PublicKey import RSA

def generate_keys():
    # Fetching usernames from user_pass.json --------------------------------------------------
    base_dir = os.path.dirname(os.path.abspath(__file__))
    server_dir = os.path.join(base_dir, 'Server')
    users_file_path = os.path.join(server_dir, 'user_pass.json')
    enhanced_dir = os.path.join(base_dir, 'Enhanced')

    try:
        with open(users_file_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print("Error loading Server/user_pass.json:", e)
        return

    # Create list of usernames from loaded json object
    try:
        if isinstance(data, list):
            usernames = [item['username'] for item in data]
            if not usernames:
                print("No usernames found in user_pass.json.")
                return
        else:
            print("Expected Server/user_pass.json to be a list of {\"username\": ...} objects.")
            return
    except Exception as e:
        print("Malformed or empty user_pass.json:", e)
        return

    # Create keypairs for each user ----------------------------------------------------------------
    for username in usernames:
        username = str(username)
        priv_name = f"{username}_private.pem"
        pub_name = f"{username}_public.pem"

        priv_path = os.path.join(base_dir, priv_name)
        pub_path = os.path.join(base_dir, pub_name)
        server_pub_path = os.path.join(server_dir, pub_name)

        # Write/Overwrite user keypair
        key = RSA.generate(2048)
        try:
            with open(priv_path, 'wb') as f:
                f.write(key.export_key('PEM'))
            with open(pub_path, 'wb') as f:
                f.write(key.publickey().export_key('PEM'))
            print(f"\nGenerated keys for user: {username}")
        except Exception as e:
            print(f"Failed generating keys for {username}:", e)

        # Copy user public key to Server/ 
        try:
            with open(pub_path, 'rb') as src, open(server_pub_path, 'wb') as dst:
                dst.write(src.read())
            print(f"Copied `{pub_name}` to Server/")
        except Exception as e:
            print(f"Failed copying `{pub_name}` to Server/:", e)

    # Create server keypair ----------------------------------------------------------------
    server_priv = os.path.join(server_dir, 'server_private.pem')
    server_pub = os.path.join(server_dir, 'server_public.pem')
    root_server_pub = os.path.join(base_dir, 'server_public.pem')

    enhanced_server_priv = os.path.join(enhanced_dir, 'server_private.pem')
    enhanced_server_pub = os.path.join(enhanced_dir, 'server_public.pem')

    # Write/Overwrite server keypair
    key = RSA.generate(2048)
    try:
        with open(server_priv, 'wb') as f:
            f.write(key.export_key('PEM'))
        with open(server_pub, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
        print(f"\nGenerated keys for server")
        # Copy server public key to root (client dir)
        with open(root_server_pub, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
        print("Copied `server_public.pem` to root (client dir)")
        # Copy server keypair to Enhanced/
        with open(enhanced_server_priv, 'wb') as f:
            f.write(key.export_key('PEM'))
        with open(enhanced_server_pub, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
        print("Copied server keys to Enhanced/")
    except Exception as e:
        print("Error creating server keys:", e)

if __name__ == "__main__":
    generate_keys()