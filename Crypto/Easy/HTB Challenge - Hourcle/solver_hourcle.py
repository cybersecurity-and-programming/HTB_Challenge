#!/usr/bin/python3
from argparse import ArgumentParser
from pwn import *
import string, os

def encrypt_func(user, target):
    target.sendlineafter(b'traveler :: ', b'1')
    if type(user) == str:
        user = user.encode()
    target.sendlineafter(b'archives :: ', user)
    target.recvuntil(b'scrolls: ')
    return bytes.fromhex(target.recvline().decode().strip())

def admin_login(password, target):
    target.sendlineafter(b'traveler :: ', b'2')
    target.sendlineafter(b'Sanctum :: ', password.encode())
    resp = target.recvline().decode().strip()
    return re.findall(r'HTB{.+}', resp)

def split_blocks(ct: bytes) -> list[bytes]:
    """Divide un ciphertext en bloques de tamaño fijo."""
    return [ct[i:i+16] for i in range(0, len(ct), 16)]

def align_prefix(block_num: int, known: str) -> str:
    """
    Calcula cuántos 'x' necesitamos para que el siguiente carácter desconocido
    del password caiga EXACTAMENTE en la última posición del bloque block_num.

    Tamaño de bloque del cifrado: 16 bytes
    Queremos que el siguiente carácter del password caiga
    justo en la última posición del bloque block_num

    Estructura del plaintext que vamos a cifrar:
    [relleno con 'x'] + [password descubierto] + [carácter candidato]
    Calculamos cuántas 'x' necesitamos para que
    (password + candidato) termine exactamente al final del bloque

    (block_num + 1) * block_size  -> número total de bytes hasta el final del bloque `block_num`
    -1                            -> dejamos sitio para el carácter candidato
    - len(password)               -> restamos lo que ya sabemos del password
    """
    plaintext = (block_num + 1) * 16 - 1 - len(known)
    return "x" * plaintext


def oracle_attack(target):
    """
    Recupera el password de 20 caracteres usando el oráculo del servidor.
    encrypt_func(user: str) -> bytes
    """
    password = ""
    block_num = 1  # el reto coloca el password en el bloque 1
    characters = string.ascii_letters + string.digits

    while len(password) < 20:

        # 1. Construir el prefijo alineado
        prefix = align_prefix(block_num, password)

        # 2. Obtener el bloque objetivo (sin candidato)
        target_block = split_blocks(encrypt_func(prefix, target))[block_num]

        # 3. Probar cada carácter posible
        for c in characters:

            # Construimos el plaintext de prueba:
            # relleno + password descubierto + carácter candidato
            # Ciframos este plaintext de prueba
            test_block = split_blocks(encrypt_func((prefix + password + c).encode(), target))[block_num]

            # Comparamos el bloque `block_num` del ciphertext de prueba
            # con el bloque objetivo que obtuvimos antes.
            #
            # Si son iguales, significa que el bloque de plaintext
            # también coincide, por lo que el carácter `c` es correcto.
            if test_block == target_block:
                password += c
                print(f"[+] Descubierto: {password}")

                # Si llenamos un bloque completo, pasamos al siguiente
                if len(password) % 16 == 0:
                    block_num += 1

                break
        else:
            print(f"[-] No se encontró carácter válido en el bloque {block_num}")
            return None

    return password

def main(ip):
    if ip in ("localhost", "127.0.0.1"):
        target = process(['python3', 'server.py'], level='error')
    else:
        host, port = ip.split(":")
        target = remote(host,port)

    password = oracle_attack(target)
    print(admin_login(password, target))
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="ip del servidor --> formato ip:port", required=True)

    args = parser.parse_args()
    main(args.ip)
