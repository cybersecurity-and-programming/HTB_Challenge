from Crypto.PublicKey import RSA
import owiener
from Crypto.Util.number import long_to_bytes, bytes_to_long

def load_pubkey(path="key.pub"):
    try:
        with open(path, "rb") as f:
            key = RSA.import_key(f.read())
        return key.n, key.e
    except FileNotFoundError:
        print("Archivo no encontrado")
        exit()

def load_encrypted_key(path="flag.enc"):
    with open(path, 'rb') as f:
        return bytes_to_long(f.read())

def main():
    n, e = load_pubkey()
    d = owiener.attack(e, n)

    if d is None:
        print("Wiener attack failed. e no es vulnerable.")
        exit()

    enc_key = load_encrypted_key()
    raw = long_to_bytes(pow(enc_key, d, n))
    print(raw)

if __name__ == "__main__":
    main()
