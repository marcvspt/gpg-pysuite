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

def decrypt_message(privkey, passwd, message):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    with open(privkey, 'rb') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)
        if import_result.count == 0:
            raise ValueError('\n[-]Failed to import private key\n')

    private_key = import_result.results[0]['fingerprint']

    with open(message, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = gpg.decrypt(encrypted_data, passphrase=passwd, always_trust=True)

    rmdir(temp_dir)
    if decrypted_data.ok:
        return decrypted_data.data.decode('utf-8')
    else:
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message decryption with PGP')
    parser.add_argument('-k', '--private-key', dest='privkey' , type=str, help='Path to PGP Private Key file', required=True)
    parser.add_argument('-p', '--passphrase', dest='passphrase', type=str, help='PGP Private Key password', required=True)
    parser.add_argument('-m', '--message-file', dest='message', type=str, help='Path to PGP Message encrypted', required=True)
    args = parser.parse_args()

    decrypted_message = decrypt_message(args.privkey, args.passphrase, args.message)

    print(decrypted_message)
