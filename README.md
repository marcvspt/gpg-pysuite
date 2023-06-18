# PGP Python Suite
In this repository we have 5 tools that use `python-gnupg` to:
* [Generate PGP key pair](keygen.py)
* [Encrypt PGP messages](encrypt.py)
* [Decrypt PGP messages](decrypt.py)
* [Signing PGP messages](sign.py)
* [Verify PGP message signature](verify.py)

This tools doesn't import the PGP keys in the machine, just the `keygen.py` export they in `.asc` files in the current directory.

## Install
```bash
git clone https://github.com/atriox2510/pgp-pysuite
cd pgp-pysuite
python3 -m pip install -r requeriments.txt
```