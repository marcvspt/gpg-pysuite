# GPG Python Suite
In this repository we have a tool that use `python-gnupg`, **GPG Python Suite** doesn't import the **GPG keys** in the machine, the keys that you can generate are going to be exported in `.asc` files on the current directory.

- [GPG Python Suite](#gpg-python-suite)
  - [Install](#install)
    - [CLI configuration](#cli-configuration)
    - [VSCode configuration](#vscode-configuration)
  - [Usage](#usage)
    - [Generate keys](#generate-keys)
    - [Encrypt messages](#encrypt-messages)
    - [Decrypt messages](#decrypt-messages)
    - [Signing messages](#signing-messages)
    - [Verify signatures](#verify-signatures)

## Install
First install `pipenv` or `python-pipenv`/`python3-pipenv` (depends how was named by your package manager). Install it with `pip`/`pip3` is possible, but in **2023**, **PyPi** recomends use your package manager to install libraries and packages.

```bash
git clone https://github.com/marcvspt/gpg-pysuite
cd gpg-pysuite
```

### CLI configuration
```bash
pipenv install
pipenv shell
```

### VSCode configuration
If you do the normal terminal instalation inside vscode terminal, you have to close and reopen the application or do this:
1. Open `Command Palette`. Linux and Windows: `Ctrl + Shift + P`. For MacOS: `Command + Shift + P`
2. Type `> clear cache and reload window`.

Now configure the python interpreter:
1. Open `Command Palette`. Linux and Windows: `Ctrl + Shift + P`. For MacOS: `Command + Shift + P`
2. Type `> python select interpreter`.
3. Select **PipEnv** option.

## Usage
```bash
$ python3 gpg_pysuite.py -h
usage: gpg_pysuite.py [-h] {generate,encrypt,decrypt,sign,verify}

GnuPG Python suite

positional arguments:
  {generate,encrypt,decrypt,sign,verify}

options:
  -h, --help            show this help message and exit
```

### Generate keys
```bash
$ python3 gpg_pysuite.py generate -h
usage: gpg_pysuite.py generate [-h] -p PASSPHRASE -n NAME -e EMAIL [-b BASE_NAME] [--bits BITS]

Generate GPG key pair RSA

options:
  -h, --help            show this help message and exit
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
$ python3 gpg_pysuite.py encrypt -h

Encrypt message with GPG

options:
  -h, --help            show this help message and exit
  -k GPG_KEY, --gpg-key GPG_KEY
                        Path to GPG public key (Asymmetric) or private key (Symmetric)
  -m MESSAGE, --message MESSAGE
                        Message to encrypt
  -o OUTFILE, --outfile OUTFILE
                        Path to save the GPG message encrypted
```

### Decrypt messages
```bash
$ python3 gpg_pysuite.py decrypt -h

Decrypt GPG encrypted message

options:
  -h, --help            show this help message and exit
  -k PRIV_KEY, --private-key PRIV_KEY
                        Path to GPG private key
  -p PASSPHRASE, --passphrase PASSPHRASE
                        GPG private key password
  -m MESSAGE, --message-file MESSAGE
                        Path to GPG message encrypted
  -o OUTFILE, --outfile OUTFILE
                        Path to save the message decrypted
```

### Signing messages
```bash
$ python3 gpg_pysuite.py sign -h
usage: gpg_pysuite.py sign [-h] -c PUBKEY -k PRIVKEY -p PASSPHRASE -m MESSAGE [-o OUTFILE]

Sign message with GPG

options:
  -h, --help            show this help message and exit
  -k PRIV_KEY, --private-key PRIV_KEY
                        Path to GPG private key
  -p PASSPHRASE, --passphrase PASSPHRASE
                        GPG Private Key password
  -m MESSAGE, --message MESSAGE
                        Message to sign
  -o OUTFILE, --outfile OUTFILE
                        Path to save the GPG sessage signed
```

### Verify signatures
The tool can verify the signatures with the **public key**.

```bash
$ python3 gpg_pysuite.py verify -h

Verify signature with GPG

options:
  -h, --help            show this help message and exit
  -c PUB_KEY, --public-key PUB_KEY
                        Path to GPG public key
  -m MESSAGE, --signed-message MESSAGE
                        Path to signed message
```
