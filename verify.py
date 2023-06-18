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

def verify_signature(pubkey, message):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    with open(pubkey, 'rb') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)
        if import_result.count == 0:
            raise ValueError('\n[-]Failed to import public key\n')

    public_key = import_result.fingerprints[0]

    with open(message, 'r') as f:
        signed_message = f.read()

    verified = gpg.verify(signed_message)

    rmdir(temp_dir)
    if verified.fingerprint == public_key and verified.valid:
        print("\n[+] La firma es válida\n")
    else:
        print("\n[!]La firma no es válida\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verify signed message with PGP')
    parser.add_argument('-c', '--public-key', dest='pubkey' , type=str, help='Path to PGP Public Key file', required=True)
    parser.add_argument('-m', '--signed-message', dest='message', type=str, help='Path to Signed message', required=True)
    args = parser.parse_args()

    verify_signature(args.pubkey, args.message)
