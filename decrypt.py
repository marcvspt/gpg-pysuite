#!/usr/bin/python3

import gnupg
import tempfile
import argparse
import subprocess
import sys

def rmdir(directory):
    subprocess.run(['rmdir', '/s', '/q', directory])

def decrypt_message(privkey, passwd, message, outfile):
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

    try:
        with open(message, 'r') as f:
            encrypted_data = f.read()
            if encrypted_data is None:
                rmdir(temp_dir)
                print("\n[!] Empty or corrupted encrypted message. Unable to decrypt\n")
                sys.exit(1)
    except:
        rmdir(temp_dir)
        print("\n[!] No such encrypted message\n")
        sys.exit(1)

    try:
        decrypted_data = gpg.decrypt(encrypted_data, passphrase=passwd, always_trust=True)
        decrypted_message = decrypted_data.data.decode('utf-8')

        rmdir(temp_dir)
        if outfile:
            try:
                with open(outfile + ".txt", 'w') as f:
                    f.write(decrypted_message)

                print('\n[+] Message decrypted saved in %s\n' % (outfile + ".txt"))
            except:
                print("\n[!] Error Saving decrypted data in a file\n")
        else:
            print('\n[+] Message decrypted successfully\n')
            print(decrypted_message)
    except:
        rmdir(temp_dir)
        print("\n[!] Error decrypting data\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Message decryption with PGP')
    parser.add_argument('-k', '--private-key', dest='privkey' , type=str, help='Path to PGP Private Key file', required=True)
    parser.add_argument('-p', '--passphrase', dest='passphrase', type=str, help='PGP Private Key password', required=True)
    parser.add_argument('-m', '--message-file', dest='message', type=str, help='Path to PGP Message encrypted', required=True)
    parser.add_argument('-o', '--outfile', dest='outfile', type=str, help='Path to save the PGP Message decrypted', required=False)
    args = parser.parse_args()

    decrypt_message(args.privkey, args.passphrase, args.message, args.outfile)
