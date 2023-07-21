# PGP Python Suite
In this repository we have a  tool that use `python-gnupg`, **PGP Python Suite** doesn't import the PGP keys in the machine, the keys that you can generate are going to be exported in `.asc` files on the current directory.

- [PGP Python Suite](#pgp-python-suite)
  - [Install](#install)
  - [Usage](#usage)
    - [Generate keys](#generate-keys)
    - [Encrypt messages](#encrypt-messages)
    - [Decrypt messages](#decrypt-messages)
    - [Signing messages](#signing-messages)
    - [Verify signatures](#verify-signatures)

## Install
```bash
git clone https://github.com/marcvspt/pgpysuite
cd pgpysuite
python3 -m pip install -r requeriments.txt
python3 pgpysuite.py -h
```

## Usage
```bash
$ python3 pgpysuite.py -h
usage: pgpysuite.py [-h] {generate,encrypt,decrypt,sign,verify} ...

PGP Python suite

positional arguments:
    {generate,encrypt,decrypt,sign,verify}

optional arguments:
    -h, --help          show this help message and exit
```

### Generate keys
```bash
$ python3 pgpysuite.py generate -h
usage: pgpysuite.py generate [-h] -p PASSPHRASE -n NAME -e EMAIL [-b BASE_NAME] [--bits BITS]

Generate PGP key pair

optional arguments:
    -h, --help          show this help message and exit
    -p PASSPHRASE, --passphrase PASSPHRASE
                        Password for the private key
    -n NAME, --name NAME  User name
    -e EMAIL, --email EMAIL
                        User e-mail
    -b BASE_NAME, --base-name BASE_NAME
                        Base name for the keys
    --bits BITS           Key length in bits
```

### Encrypt messages
The tool can encrypt the messages with the **public key** (Asymmetric) and **private key** (Symmetric).
```bash
$ python3 pgpysuite.py encrypt -h
usage: pgpysuite.py encrypt [-h] -k PGPKEY -m MESSAGE [-o OUTFILE]

Encrypt message with PGP

optional arguments:
    -h, --help          show this help message and exit
    -k PGPKEY, --pgp-key PGPKEY
                        Path to PGP public pey (Asymmetric) or private key (Symmetric)
    -m MESSAGE, --message MESSAGE
                        Message to encrypt
    -o OUTFILE, --outfile OUTFILE
                        Path to save the PGP message encrypted
```

### Decrypt messages
```bash
$ python3 pgpysuite.py decrypt -h
usage: pgpysuite.py decrypt [-h] -k PRIVKEY -p PASSPHRASE -m MESSAGE [-o OUTFILE]

Decrypt PGP encrypted message

optional arguments:
  -h, --help            show this help message and exit
  -k PRIVKEY, --private-key PRIVKEY
                        Path to PGP private key
  -p PASSPHRASE, --passphrase PASSPHRASE
                        PGP private key password
  -m MESSAGE, --message-file MESSAGE
                        Path to PGP message encrypted
  -o OUTFILE, --outfile OUTFILE
                        Path to save the message decrypted
```

### Signing messages
```bash
$ python3 pgpysuite.py sign -h
usage: pgpysuite.py sign [-h] -c PUBKEY -k PRIVKEY -p PASSPHRASE -m MESSAGE [-o OUTFILE]

Sign message with PGP

optional arguments:
    -h, --help          show this help message and exit
    -c PUBKEY, --public-key PUBKEY
                        Path to PGP Public Key file
    -k PRIVKEY, --private-key PRIVKEY
                        Path to PGP Private Key file
    -p PASSPHRASE, --passphrase PASSPHRASE
                        PGP Private Key password
    -m MESSAGE, --message MESSAGE
                        Message to sign
    -o OUTFILE, --outfile OUTFILE
                        Path to save the PGP sessage signed
```

### Verify signatures
The tool can verify the signatures with the **public key** (Asymmetric) and **private key** (Symmetric).
```bash
$ python3 pgpysuite.py verify -h
usage: pgpysuite.py verify [-h] -k PGPKEY -m MESSAGE

Verify signature with PGP

optional arguments:
    -h, --help          show this help message and exit
    -k PGPKEY, --pgp-key PGPKEY
                        Path to PGP public key (Asymmetric) or private key (Symmetric)
    -m MESSAGE, --signed-message MESSAGE
                        Path to signed message
```