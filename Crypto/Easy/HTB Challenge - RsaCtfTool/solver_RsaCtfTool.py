from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

def load_pubkey(path="pubkey.pem"):
    """Carga n y e desde un archivo PEM."""
    try:
        with open(path, "rb") as f:
            key = RSA.import_key(f.read())
        return key.n, key.e
    except FileNotFoundError:
        print("Archivo no encontrado")
        exit()

def factor_n(n):
    """Factoriza n = p^3 aprovechando que p es la raíz cúbica exacta."""
    p, exact = iroot(n, 3)
    if exact != True:
        raise ValueError("n no es un cubo perfecto, no es p^3.")
    return int(p)

def compute_private_exponent(e, p):
    """Calcula d usando φ(n) = p^2 (p - 1)."""
    phi = p**2 * (p - 1)
    return pow(e, -1, phi)

def load_encrypted_key(path="key"):
    """Carga la clave AES cifrada (en hex)."""
    with open(path) as f:
        return int(f.read().strip(), 16)


def extract_aes_key(raw):
    """
    Extrae la clave AES del resultado RSA.
    En este reto, la clave está directamente al final del bloque.
    """
    # Probamos tamaños válidos de AES: 32, 24, 16 bytes
    for size in (32, 24, 16):
        candidate = raw[-size:]
        try:
            AES.new(candidate, AES.MODE_ECB)
            return candidate
        except ValueError:
            continue
    raise ValueError("No se encontró una clave AES válida en el bloque RSA.")


def decrypt_flag(aes_key, path="flag.txt.aes"):
    """Descifra la flag con AES-ECB."""
    aes = AES.new(aes_key, AES.MODE_ECB)
    with open(path, "rb") as f:
        ciphertext = f.read().strip()

    if len(ciphertext) % 16 != 0:
        raise ValueError("El ciphertext no está alineado a 16 bytes.")

    return aes.decrypt(ciphertext)

def main():
    n, e = load_pubkey()
    p = factor_n(n)
    d = compute_private_exponent(e, p)

    enc_key = load_encrypted_key()
    raw = long_to_bytes(pow(enc_key, d, n))

    aes_key = extract_aes_key(raw)
    print(f"[+] AES key encontrada: {aes_key.hex()}")

    flag = decrypt_flag(aes_key)
    print(f"[+] Flag descifrada: {flag.decode(errors="ignore")}")

if __name__ == "__main__":
    main()

