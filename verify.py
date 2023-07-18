#!/usr/bin/python3

import gnupg
import tempfile
import argparse
import subprocess
import sys

def rmdir(directory):
    subprocess.run(['rm', '-rf', directory])

def verify_signature(pubkey, message):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    try:
        with open(pubkey, 'rb') as f:
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

    public_key = import_result.fingerprints[0]

    try:
        with open(message, 'r') as f:
            signed_message = f.read()
            if signed_message is None:
                rmdir(temp_dir)
                print("\n[!] Empty or corrupted signed message. Unable to verify\n")
                sys.exit(1)
    except:
        rmdir(temp_dir)
        print("\n[!] No such message to verify\n")
        sys.exit(1)

    try:
        verified = gpg.verify(signed_message)
    except:
        rmdir(temp_dir)
        print("\n[!] Error verifing signature\n")
        sys.exit(1)

    rmdir(temp_dir)
    if verified.fingerprint == public_key and verified.valid:
        print("\n[+] Valid signature\n")
    else:
        print("\n[-] Invalid signature\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verify signed message with PGP')
    parser.add_argument('-c', '--public-key', dest='pubkey' , type=str, help='Path to PGP Public Key file', required=True)
    parser.add_argument('-m', '--signed-message', dest='message', type=str, help='Path to Signed message', required=True)
    args = parser.parse_args()

    verify_signature(args.pubkey, args.message)
