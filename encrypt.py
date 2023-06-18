#!/usr/bin/python3

import gnupg
import tempfile
import argparse
import subprocess
import os

def rmdir(directory):
    sistema_operativo = os.name
    if sistema_operativo == 'posix':
        subprocess.run(['rm', '-rf', directory])
    elif sistema_operativo == 'nt':
        subprocess.run(['rmdir', '/s', '/q', directory])

def encrypt_message(pubkey, message):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    with open(pubkey, 'rb') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)
        if import_result.count == 0:
            raise ValueError('\n[-]Failed to import public key\n')

    public_key = import_result.fingerprints[0]

    encrypted_data = gpg.encrypt(message, public_key, always_trust=True)

    rmdir(temp_dir)
    if encrypted_data.ok:
        return encrypted_data.data.decode('utf-8')
    else:
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message encryption with PGP')
    parser.add_argument('-c', '--public-key', dest='pubkey' , type=str, help='Path to PGP Public Key file', required=True)
    parser.add_argument('-m', '--message', dest='message', type=str, help='Message to encrypt', required=True)
    args = parser.parse_args()

    encrypted_message = encrypt_message(args.pubkey, args.message)

    print(encrypted_message)