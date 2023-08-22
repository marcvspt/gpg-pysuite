#!/usr/bin/python3

"""
GPG Python Suite helps cryptographic processes with 'Pretty Good Privacy' using python-gnupg to:
- Generate GPG-RSA key pair.
- Message encryption.
- Message decryption.
- Message signing.
- Message signature verification.

GPGPySuite doesn't import the GPG keys in the machine.
"""

import tempfile
import argparse
import subprocess
import sys
import gnupg

class GPGPySuite:
    """Class: use functions from python-gnupg"""

    def __init__(self):
        """Private method: constructor (create temp-home gnupg directory)"""
        self._temp_dir = tempfile.mkdtemp()
        self._format_encoding = 'utf-8'
        self._symbol_error = '[x]'
        self._symbol_success = '[+]'

    def __cleanup__(self, directory):
        """Private method: delete temp-home gnupg directory"""
        try:
            subprocess.run(['rm', '-rf', directory], check=False)
        except subprocess.CalledProcessError:
            print(f'{self._symbol_error} Error cleaning up temp-gnupg home directory.')
            sys.exit(1)

    def __import_key__(self, gpg, key_file):
        """Private method: import gpg keys"""
        try:
            with open(key_file, 'r', encoding=self._format_encoding) as file_name:
                content = file_name.read()
                data = gpg.import_keys(content)
        except (PermissionError, OSError) as error:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error reading key:\n {str(error)}')
            sys.exit(1)

        return data.fingerprints[0]

    def __export_key__(self, gpg, key_file, base_name, passwd, is_private=False):
        """Private method: export gpg keys"""
        fingerprint = key_file.fingerprint
        key_data = gpg.export_keys(fingerprint, secret=is_private, passphrase=passwd)
        extension = '.priv.asc' if is_private else '.pub.asc'
        file_name = base_name + extension

        try:
            with open(file_name, 'w', encoding=self._format_encoding) as content:
                content.write(key_data)
        except (PermissionError, OSError) as error:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error exporting key:\n {str(error)}')
            sys.exit(1)

    def __import_data__(self, data):
        """Private method: import data like plaintext, encrypted or sigened messages"""
        try:
            with open(data, 'r', encoding=self._format_encoding) as file_name:
                content = file_name.read()
                if content is None:
                    self.__cleanup__(self._temp_dir)
                    print(f'\n{self._symbol_error} Empty or corrupted file.\n')
                    sys.exit(1)

                return content
        except (PermissionError, OSError) as error:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Failed reading file:\n {str(error)}')
            sys.exit(1)

    def __export_data__(self, data, outfile):
        """Private method: export data like plaintext, encrypted or signed messages"""
        try:
            with open(outfile, 'w', encoding=self._format_encoding) as file_name:
                file_name.write(data)
                print(f'\n{self._symbol_success} Message encrypted saved in {outfile}.\n')
        except (PermissionError, OSError) as error:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error saving message:\n {str(error)}')
            sys.exit(1)

    def gen_keys(self, passwd, name, email, base_name, bits):
        """Public method: generate GnuPG key pair"""
        gpg = gnupg.GPG(gnupghome=self._temp_dir)

        try:
            input_data = gpg.gen_key_input(
                key_type='RSA',
                key_length=bits,
                passphrase=passwd,
                name_real=name,
                name_email=email
            )

            key = gpg.gen_key(input_data)
        except NotImplementedError as gen_err:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error generating GPG key pair:\n {str(gen_err)}')
            sys.exit(1)

        self.__export_key__(gpg, key, base_name, passwd, is_private=True)
        self.__export_key__(gpg, key, base_name, passwd, is_private=False)

        self.__cleanup__(self._temp_dir)
        print(f'\n{self._symbol_success} Keys generated successfully.\n')

    def encrypt_message(self, gpg_file, message, outfile):
        """Public method: encrypt messages"""
        gpg = gnupg.GPG(gnupghome=self._temp_dir)

        gpg_key = self.__import_key__(gpg, gpg_file)

        try:
            encrypted_data = gpg.encrypt(message, gpg_key, always_trust=True)
            encrypted_message = encrypted_data.data.decode(self._format_encoding)

            self.__cleanup__(self._temp_dir)
            if outfile:
                outfile = outfile + ".encrypted"
                self.__export_data__(encrypted_message, outfile)
            else:
                print(f'\n{self._symbol_success} Message encrypted successfully.\n')
                print(encrypted_message)
        except NotImplementedError as encrypt_err:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_success} Error encrypting message:\n {str(encrypt_err)}')
            sys.exit(1)

    def decrypt_message(self, priv_key, passwd, message, outfile):
        """Public method: decrypt messages"""
        gpg = gnupg.GPG(gnupghome=self._temp_dir)

        self.__import_key__(gpg, priv_key)
        encrypted_data = self.__import_data__(message)

        try:
            decrypted_data = gpg.decrypt(encrypted_data, passphrase=passwd, always_trust=True)
            if not decrypted_data.ok:
                self.__cleanup__(self._temp_dir)
                print(f'\n{self._symbol_error} Incorrect passphrase.\n')
                sys.exit(1)

            decrypted_message = decrypted_data.data.decode(self._format_encoding)

            self.__cleanup__(self._temp_dir)
            if outfile:
                outfile = outfile + ".txt"
                self.__export_data__(decrypted_message, outfile)
            else:
                print(f'\n{self._symbol_success} Message decrypted successfully:\n')
                print(decrypted_message)
        except NotImplementedError as encrypt_err:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error decrypting message:\n {str(encrypt_err)}')
            sys.exit(1)

    def sign_message(self, gpg_file, passwd, message, outfile):
        """Public method: sign messages"""
        gpg = gnupg.GPG(gnupghome=self._temp_dir)

        priv_key = self.__import_key__(gpg, gpg_file)[0]

        try:
            signed_data = gpg.sign(message, keyid=priv_key, passphrase=passwd)
            if not signed_data.status == 'signature created':
                self.__cleanup__(self._temp_dir)
                print(f'\n{self._symbol_error} Incorrect passphrase.\n')
                sys.exit(1)

            signed_message = signed_data.data.decode(self._format_encoding)

            self.__cleanup__(self._temp_dir)
            if outfile:
                outfile = outfile + ".signed"
                self.__export_data__(signed_message, outfile)
            else:
                print(f'\n{self._symbol_success} Message signed successfully:\n')
                print(signed_message)
        except NotImplementedError as sign_err:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error signing message:\n {str(sign_err)}')
            sys.exit(1)

    def verify_signature(self, gpg_file, message):
        """Public method: verify signature"""
        gpg = gnupg.GPG(gnupghome=self._temp_dir)

        pub_key = self.__import_key__(gpg, gpg_file)
        signed_message = self.__import_data__(message)

        try:
            verified = gpg.verify(signed_message)
        except NotImplementedError as verify_err:
            self.__cleanup__(self._temp_dir)
            print(f'\n{self._symbol_error} Error verifying signature:\n {str(verify_err)}')
            sys.exit(1)

        self.__cleanup__(self._temp_dir)
        if verified.fingerprint == pub_key and verified.valid:
            print(f'\n{self._symbol_success} Valid signature\n')
        else:
            print(f'\n{self._symbol_error} Invalid signature\n')

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='GnuPG Python suite')
    subparsers = parser.add_subparsers(dest='command')

    # GENERATE KEYS
    gen_parser = subparsers.add_parser('generate',
                                       description='Generate GPG key pair RSA')
    gen_parser.add_argument('-p', '--passphrase',
                            dest='passphrase',
                            type=str,
                            help='Password for the private key',
                            required=True)
    gen_parser.add_argument('-n', '--name',
                            dest='name',
                            type=str,
                            help='User name',
                            required=True)
    gen_parser.add_argument('-e', '--email',
                            dest='email', type=str,
                            help='User e-mail',
                            required=True)
    gen_parser.add_argument('-b', '--base-name',
                            dest='base_name', type=str,
                            help='Base name for the keys',
                            required=False,
                            default='file_gpg')
    gen_parser.add_argument('--bits',
                            dest='bits',
                            type=int,
                            help='Key length in bits',
                            required=False,
                            default=2048)

    # ENCRYPT MESSAGE
    enc_parser = subparsers.add_parser('encrypt',
                                       description='Encrypt message with GPG')
    enc_parser.add_argument('-k', '--gpg-key',
                            dest='gpg_key',
                            type=str,
                            help='Path to GPG public key (Asymmetric) or private key (Symmetric)',
                            required=True)
    enc_parser.add_argument('-m', '--message',
                            dest='message',
                            type=str,
                            help='Message to encrypt',
                            required=True)
    enc_parser.add_argument('-o', '--outfile',
                            dest='outfile', type=str,
                            help='Path to save the GPG message encrypted',
                            required=False)

    # DECRYPT MESSAGES
    dec_parser = subparsers.add_parser('decrypt',
                                       description='Decrypt GPG encrypted message')
    dec_parser.add_argument('-k', '--private-key',
                            dest='priv_key',
                            type=str,
                            help='Path to GPG private key',
                            required=True)
    dec_parser.add_argument('-p', '--passphrase',
                            dest='passphrase',
                            type=str,
                            help='GPG private key password',
                            required=True)
    dec_parser.add_argument('-m', '--message-file',
                            dest='message',
                            type=str,
                            help='Path to GPG message encrypted',
                            required=True)
    dec_parser.add_argument('-o', '--outfile',
                            dest='outfile',
                            type=str,
                            help='Path to save the message decrypted',
                            required=False)

    # SIGNING MESSAGES
    sign_parser = subparsers.add_parser('sign',
                                        description='Sign message with GPG')
    sign_parser.add_argument('-k', '--private-key',
                             dest='priv_key',
                             type=str,
                             help='Path to GPG private key',
                             required=True)
    sign_parser.add_argument('-p', '--passphrase',
                             dest='passphrase',
                             type=str,
                             help='GPG Private Key password',
                             required=True)
    sign_parser.add_argument('-m', '--message',
                             dest='message',
                             type=str,
                             help='Message to sign',
                             required=True)
    sign_parser.add_argument('-o', '--outfile',
                             dest='outfile',
                             type=str,
                             help='Path to save the GPG sessage signed',
                             required=False)

    # VERIFY SIGNATURES
    verify_parser = subparsers.add_parser('verify',
                                          description='Verify signature with GPG')
    verify_parser.add_argument('-c', '--public-key',
                               dest='pub_key', type=str,
                               help='Path to GPG public key',
                               required=True)
    verify_parser.add_argument('-m', '--signed-message',
                               dest='message',
                               type=str,
                               help='Path to signed message',
                               required=True)

    args = parser.parse_args()
    gpg_py = GPGPySuite()

    if args.command == 'generate':
        gpg_py.gen_keys(args.passphrase,
                        args.name,
                        args.email,
                        args.base_name,
                        args.bits)
    elif args.command == 'encrypt':
        gpg_py.encrypt_message(args.gpg_key,
                               args.message,
                               args.outfile)
    elif args.command == 'decrypt':
        gpg_py.decrypt_message(args.priv_key,
                               args.passphrase,
                               args.message,
                               args.outfile)
    elif args.command == 'sign':
        gpg_py.sign_message(args.priv_key,
                            args.passphrase,
                            args.message,
                            args.outfile)
    elif args.command == 'verify':
        gpg_py.verify_signature(args.pub_key,
                                args.message)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
