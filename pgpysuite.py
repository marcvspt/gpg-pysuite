#!/usr/bin/python3

import gnupg
import tempfile
import argparse
import subprocess
import sys

class PGPPySuite:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()

    # DELETE TEMP GNUPG DIRECTORIES
    def rmdir(self, directory):
        subprocess.run(['rm', '-rf', directory])

    # GENERATE KEYS
    def gen_keys(self, passwd, name, email, base_name, bits):
        gpg = gnupg.GPG(gnupghome=self.temp_dir)

        try:
            input_data = gpg.gen_key_input(
                key_type="RSA",
                key_length=bits,
                passphrase=passwd,
                name_real=name,
                name_email=email
            )

            key = gpg.gen_key(input_data)
        except:
            self.rmdir(self.temp_dir)
            print("\n[-] Error generating PGP key pair\n")
            sys.exit(1)

        try:
            public_key = gpg.export_keys(key.fingerprint)
            with open(base_name + '.pub.asc', 'w') as f:
                f.write(public_key)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] Error exporting public key\n")
            sys.exit(1)

        try:
            private_key = gpg.export_keys(key.fingerprint, secret=True, passphrase=passwd)
            with open(base_name + '.key.asc', 'w') as f:
                f.write(private_key)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] Error exporting private key\n")
            sys.exit(1)

        self.rmdir(self.temp_dir)
        print('\n[+] Keys generated successfully\n')

    # ENCRYPT MESSAGE
    def encrypt_message(self, pgpkey, message, outfile):
        gpg = gnupg.GPG(gnupghome=self.temp_dir)

        try:
            with open(pgpkey, 'r') as f:
                key_data = f.read()
                import_result = gpg.import_keys(key_data)
                if import_result.count == 0:
                    self.rmdir(self.temp_dir)
                    print('\n[!] Failed to import public key\n')
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such public/private key\n")
            sys.exit(1)

        try:
            pgp_key = import_result.fingerprints[0]
            encrypted_data = gpg.encrypt(message, pgp_key, always_trust=True)
            encrypted_message = encrypted_data.data.decode('utf-8')

            self.rmdir(self.temp_dir)
            if outfile:
                try:
                    outfile = outfile + ".encrypted"
                    with open(outfile, 'w') as f:
                        f.write(encrypted_message)

                    print('\n[+] Message encrypted saved in %s\n' % outfile)
                except:
                    print("\n[!] Error Saving encrypted data in a file\n")
            else:
                print('\n[+] Message encrypted successfully\n')
                print(encrypted_message)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] Error encrypting data\n")
            sys.exit(1)

    # DECRYPT MESSAGES
    def decrypt_message(self, privkey, passwd, message, outfile):
        gpg = gnupg.GPG(gnupghome=self.temp_dir)

        try:
            with open(privkey, 'r') as f:
                key_data = f.read()
                import_result = gpg.import_keys(key_data)
                if import_result.count == 0:
                    self.rmdir(self.temp_dir)
                    print('\n[!] Failed to import private key\n')
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such private key\n")
            sys.exit(1)

        try:
            with open(message, 'r') as f:
                encrypted_data = f.read()
                if encrypted_data is None:
                    self.rmdir(self.temp_dir)
                    print("\n[!] Empty or corrupted encrypted message. Unable to decrypt\n")
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such encrypted message\n")
            sys.exit(1)

        try:
            decrypted_data = gpg.decrypt(encrypted_data, passphrase=passwd, always_trust=True)
            #pdb.set_trace()
            if not decrypted_data.ok:
                self.rmdir(self.temp_dir)
                print("\n[!] Incorrect passphrase\n")
                sys.exit(1)

            decrypted_message = decrypted_data.data.decode('utf-8')

            self.rmdir(self.temp_dir)
            if outfile:
                try:
                    outfile = outfile + ".txt"
                    with open(outfile, 'w') as f:
                        f.write(decrypted_message)

                    print('\n[+] Message decrypted saved in %s\n' % outfile)
                except:
                    print("\n[!] Error Saving decrypted data in a file\n")
            else:
                print('\n[+] Message decrypted successfully\n')
                print(decrypted_message)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] Error decrypting data\n")

    # SIGNING MESSAGES
    def sign_message(self, pubkey, privkey, passwd, message, outfile):
        gpg = gnupg.GPG(gnupghome=self.temp_dir)

        try:
            with open(privkey, 'r') as f:
                key_data = f.read()
                import_result = gpg.import_keys(key_data)
                if import_result.count == 0:
                    self.rmdir(self.temp_dir)
                    print('\n[!] Failed to import private key\n')
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such private key\n")
            sys.exit(1)

        private_key = import_result.results[0]['fingerprint']

        try:
            with open(pubkey, 'r') as f:
                key_data = f.read()
                import_result = gpg.import_keys(key_data)
                if import_result.count == 0:
                    self.rmdir(self.temp_dir)
                    print('\n[!] Failed to import public key\n')
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such public key\n")
            sys.exit(1)

        try:
            signed_data = gpg.sign(message, keyid=private_key, passphrase=passwd)
            if not signed_data.status == 'signature created':
                self.rmdir(self.temp_dir)
                print("\n[!] Incorrect passphrase\n")
                sys.exit(1)

            verification_result = gpg.verify(signed_data.data)
            signed_message = signed_data.data.decode('utf-8')

            self.rmdir(self.temp_dir)
            if outfile:
                try:
                    outfile = outfile + ".signed"
                    with open(outfile, 'w') as f:
                        f.write(signed_message)

                    print('\n[+] Message signed saved in %s\n' % outfile)
                except:
                    print("\n[!] Error Saving signed data in a file\n")
            else:
                print('\n[+] Message signed successfully\n')
                print(signed_message)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] Error signing message\n")
            sys.exit(1)

    # VERIFY SIGNATURES
    def verify_signature(self, pgpkey, message):
        gpg = gnupg.GPG(gnupghome=self.temp_dir)

        try:
            with open(pgpkey, 'r') as f:
                key_data = f.read()
                import_result = gpg.import_keys(key_data)
                if import_result.count == 0:
                    self.rmdir(self.temp_dir)
                    print('\n[!] Failed to import public key\n')
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such public/private key\n")
            sys.exit(1)

        pgp_key = import_result.fingerprints[0]

        try:
            with open(message, 'r') as f:
                signed_message = f.read()
                if signed_message is None:
                    self.rmdir(self.temp_dir)
                    print("\n[!] Empty or corrupted signed message. Unable to verify\n")
                    sys.exit(1)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] No such message to verify\n")
            sys.exit(1)

        try:
            verified = gpg.verify(signed_message)
        except:
            self.rmdir(self.temp_dir)
            print("\n[!] Error verifying signature\n")
            sys.exit(1)

        self.rmdir(self.temp_dir)
        if verified.fingerprint == pgp_key and verified.valid:
            print("\n[+] Valid signature\n")
        else:
            print("\n[-] Invalid signature\n")

def main():
    parser = argparse.ArgumentParser(description='PGP Python suite')
    subparsers = parser.add_subparsers(dest='command')

    # GENERATE KEYS
    gen_parser = subparsers.add_parser('generate', description='Generate PGP key pair RSA')
    gen_parser.add_argument('-p', '--passphrase', dest='passphrase', type=str, help='Password for the private key', required=True)
    gen_parser.add_argument('-n', '--name', dest='name', type=str, help='User name', required=True)
    gen_parser.add_argument('-e', '--email', dest='email', type=str, help='User e-mail', required=True)
    gen_parser.add_argument('-b', '--base-name', dest='base_name', type=str, help='Base name for the keys', required=False, default='key_pgp')
    gen_parser.add_argument('--bits', dest='bits', type=int, help='Key length in bits', required=False, default=2048)

    # ENCRYPT MESSAGE
    enc_parser = subparsers.add_parser('encrypt', description='Encrypt message with PGP')
    enc_parser.add_argument('-k', '--pgp-key', dest='pgpkey', type=str, help='Path to PGP public key (Asymmetric) or private key (Symmetric)', required=True)
    enc_parser.add_argument('-m', '--message', dest='message', type=str, help='Message to encrypt', required=True)
    enc_parser.add_argument('-o', '--outfile', dest='outfile', type=str, help='Path to save the PGP message encrypted', required=False)

    # DECRYPT MESSAGES
    dec_parser = subparsers.add_parser('decrypt', description='Decrypt PGP encrypted message')
    dec_parser.add_argument('-k', '--private-key', dest='privkey', type=str, help='Path to PGP private key', required=True)
    dec_parser.add_argument('-p', '--passphrase', dest='passphrase', type=str, help='PGP private key password', required=True)
    dec_parser.add_argument('-m', '--message-file', dest='message', type=str, help='Path to PGP message encrypted', required=True)
    dec_parser.add_argument('-o', '--outfile', dest='outfile', type=str, help='Path to save the message decrypted', required=False)

    # SIGNING MESSAGES
    sign_parser = subparsers.add_parser('sign', description='Sign message with PGP')
    sign_parser.add_argument('-c', '--public-key', dest='pubkey', type=str, help='Path to PGP Public Key file', required=True)
    sign_parser.add_argument('-k', '--private-key', dest='privkey', type=str, help='Path to PGP Private Key file', required=True)
    sign_parser.add_argument('-p', '--passphrase', dest='passphrase', type=str, help='PGP Private Key password', required=True)
    sign_parser.add_argument('-m', '--message', dest='message', type=str, help='Message to sign', required=True)
    sign_parser.add_argument('-o', '--outfile', dest='outfile', type=str, help='Path to save the PGP sessage signed', required=False)

    # VERIFY SIGNATURES
    verify_parser = subparsers.add_parser('verify', description='Verify signature with PGP')
    verify_parser.add_argument('-k', '--pgp-key', dest='pgpkey', type=str, help='Path to PGP public key (Asymmetric) or private key (Symmetric)', required=True)
    verify_parser.add_argument('-m', '--signed-message', dest='message', type=str, help='Path to signed message', required=True)

    args = parser.parse_args()
    pgppy = PGPPySuite()

    if args.command == 'generate':
        pgppy.gen_keys(args.passphrase, args.name, args.email, args.base_name, args.bits)
    elif args.command == 'encrypt':
        pgppy.encrypt_message(args.pgpkey, args.message, args.outfile)
    elif args.command == 'decrypt':
        pgppy.decrypt_message(args.privkey, args.passphrase, args.message, args.outfile)
    elif args.command == 'sign':
        pgppy.sign_message(args.pubkey, args.privkey, args.passphrase, args.message, args.outfile)
    elif args.command == 'verify':
        pgppy.verify_signature(args.pgpkey, args.message)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()