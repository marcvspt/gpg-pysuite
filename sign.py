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

def sign_text(pubkey, privkey, passwd, message):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    with open(privkey, 'rb') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)
        if import_result.count == 0:
            raise ValueError('\n[-]Failed to import private key\n')

    private_key = import_result.results[0]['fingerprint']

    with open(pubkey, 'rb') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)
        if import_result.count == 0:
            raise ValueError('\n[-]Failed to import public key\n')

    signed_data = gpg.sign(message, keyid=private_key, passphrase=passwd)
    verification_result = gpg.verify(signed_data.data)

    rmdir(temp_dir)
    if verification_result.valid:
        return signed_data.data.decode()
    else:
        raise ValueError('\n[!]Signature verification failed')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message signing with PGP')
    parser.add_argument('-c', '--public-key', dest='pubkey' , type=str, help='Path to PGP Public Key file', required=True)
    parser.add_argument('-k', '--private-key', dest='privkey' , type=str, help='Path to PGP Private Key file', required=True)
    parser.add_argument('-p', '--passphrase', dest='passphrase' , type=str, help='PGP Private Key password', required=True)
    parser.add_argument('-m', '--message', dest='message', type=str, help='Message to sign', required=True)
    args = parser.parse_args()

    signed_text = sign_text(args.pubkey, args.privkey, args.passphrase, args.message)
    print(signed_text)