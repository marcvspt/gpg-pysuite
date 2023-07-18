#!/usr/bin/python3

import gnupg
import tempfile
import argparse
import subprocess
import sys

def rmdir(directory):
    subprocess.run(['rm', '-rf', directory])

def sign_message(pubkey, privkey, passwd, message, outfile):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    try:
        with open(privkey, 'r') as f:
            key_data = f.read()
            import_result = gpg.import_keys(key_data)
            if import_result.count == 0:
                rmdir(temp_dir)
                print('\n[!] Failed to import private key\n')
                sys.exit(1)
    except:
        rmdir(temp_dir)
        print("\n[!] No such private key\n")
        sys.exit(1)

    private_key = import_result.results[0]['fingerprint']

    try:
        with open(pubkey, 'r') as f:
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
        signed_data = gpg.sign(message, keyid=private_key, passphrase=passwd)
        verification_result = gpg.verify(signed_data.data)
        signed_message = signed_data.data.decode('utf-8')

        rmdir(temp_dir)
        if outfile:
            try:
                with open(outfile + ".signed", 'w') as f:
                    f.write(signed_message)

                print('\n[+] Message signed saved in %s\n' % (outfile + ".signed"))
            except:
                print("\n[!] Error Saving signed data in a file\n")
        else:
            print('\n[+] Message signed successfully\n')
            print(signed_message)
    except:
        rmdir(temp_dir)
        print("\n[!] Error signing message\n")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message signing with PGP')
    parser.add_argument('-c', '--public-key', dest='pubkey' , type=str, help='Path to PGP Public Key file', required=True)
    parser.add_argument('-k', '--private-key', dest='privkey' , type=str, help='Path to PGP Private Key file', required=True)
    parser.add_argument('-p', '--passphrase', dest='passphrase' , type=str, help='PGP Private Key password', required=True)
    parser.add_argument('-m', '--message', dest='message', type=str, help='Message to sign', required=True)
    parser.add_argument('-o', '--outfile', dest='outfile', type=str, help='Path to save the PGP Message signed', required=False)
    args = parser.parse_args()

    sign_message(args.pubkey, args.privkey, args.passphrase, args.message, args.outfile)
