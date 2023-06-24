#!/usr/bin/python3

import gnupg
import tempfile
import argparse
import subprocess
import os
import sys

def rmdir(directory):
    sistema_operativo = os.name
    if sistema_operativo == 'posix':
        subprocess.run(['rm', '-rf', directory])
    elif sistema_operativo == 'nt':
        subprocess.run(['rmdir', '/s', '/q', directory])

def decrypt_message(privkey, passwd, message):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    with open(privkey, 'rb') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)
        if import_result.count == 0:
            rmdir(temp_dir)
            print('\n[!] Failed to import private key\n')
            sys.exit(1)

    with open(message, 'rb') as f:
        encrypted_data = f.read()
        if encrypted_data is None:
            rmdir(temp_dir)
            print("\n[!] Empty or corrupted encrypted message. Unable to decrypt\n")
            sys.exit(1)

    decrypted_data = gpg.decrypt(encrypted_data, passphrase=passwd, always_trust=True)

    rmdir(temp_dir)
    if decrypted_data.ok:
        print('\n[+] Message decrypted successfully\n')
        return decrypted_data.data.decode('utf-8')
    else:
        return "\n[-] Error decrypting data\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message decryption with PGP')
    parser.add_argument('-k', '--private-key', dest='privkey' , type=str, help='Path to PGP Private Key file', required=True)
    parser.add_argument('-p', '--passphrase', dest='passphrase', type=str, help='PGP Private Key password', required=True)
    parser.add_argument('-m', '--message-file', dest='message', type=str, help='Path to PGP Message encrypted', required=True)
    args = parser.parse_args()

    decrypted_message = decrypt_message(args.privkey, args.passphrase, args.message)
    print(decrypted_message)