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

def gen_keys(passwd, name, email, base_name, bits):
    temp_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=temp_dir)

    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=bits,
        passphrase=passwd,
        name_real=name,
        name_email=email
    )

    key = gpg.gen_key(input_data)

    public_key = gpg.export_keys(key.fingerprint)
    private_key = gpg.export_keys(key.fingerprint, secret=True, passphrase=passwd)

    with open(base_name + '.pub.asc', 'w') as file:
        file.write(public_key)

    with open(base_name + '.key.asc', 'w') as file:
        file.write(private_key)

    rmdir(temp_dir)
    print('\n[+] Keys generated successfully\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='PGP Key pair RSA generator')
    parser.add_argument('-p', '--passphrase', dest='passphrase' , type=str, help='Password for the private key', required=True)
    parser.add_argument('-n', '--name', dest='name' , type=str, help='User real name', required=True)
    parser.add_argument('-e', '--email', dest='email' , type=str, help='User e-mail', required=True)
    parser.add_argument('-b', '--base-name', dest='base_name', type=str, help='Base name for the keys', required=False, default='keypgp_uwu')
    parser.add_argument('--bits', dest='bits', type=int, help='Key length in bits', required=False, default=2048)
    args = parser.parse_args()

    gen_keys(args.passphrase, args.name, args.email, args.base_name, args.bits)
