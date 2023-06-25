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

def encrypt_message(pgpkey, message, outfile):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    try:
        with open(pgpkey, 'r') as f:
            key_data = f.read()
            import_result = gpg.import_keys(key_data)
            if import_result.count == 0:
                rmdir(temp_dir)
                print('\n[!] Failed to import public key\n')
                sys.exit(1)
    except:
        rmdir(temp_dir)
        print("\n[!] No such public key\n")
        sys.exit(1)

    try:
        pgp_key = import_result.fingerprints[0]
        encrypted_data = gpg.encrypt(message, pgp_key, always_trust=True)
        encrypted_message = encrypted_data.data.decode('utf-8')

        rmdir(temp_dir)
        if outfile:
            try:
                with open(outfile + ".encrypted", 'w') as f:
                    f.write(encrypted_message)

                print('\n[+] Message encrypted saved in %s\n' % (outfile + ".encrypted"))
            except:
                print("\n[!] Error Saving encrypted data in a file\n")
        else:
            print('\n[+] Message encrypted successfully\n')
            print(encrypted_message)
    except:
        rmdir(temp_dir)
        print("\n[!] Error encrypting data\n")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message encryption with PGP')
    parser.add_argument('-k', '--pgp-key', dest='pgpkey' , type=str, help='Path to PGP Public Key (Asymmetric) or Private Key (Symmetric)', required=True)
    parser.add_argument('-m', '--message', dest='message', type=str, help='Message to encrypt', required=True)
    parser.add_argument('-o', '--outfile', dest='outfile', type=str, help='Path to save the PGP Message encrypted', required=False)
    args = parser.parse_args()

    encrypt_message(args.pgpkey, args.message, args.outfile)