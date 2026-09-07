#!/usr/bin/env python3
def solve_vhdlock(filename='out.txt'):
    try:
        with open(filename) as f:
            # Leemos y filtramos líneas vacías de forma segura
            out = [tuple(map(int, line.split())) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: No se encontró el archivo '{filename}'")
        return

    if not out:
        print("[-] Error: El archivo está vacío.")
        return

    # 1. AUTO-DETECCIÓN DE LA CLAVE (Sabiendo que la primera letra es 'H')
    # 'H' en ASCII es 72 -> Binario: 0100 1000
    # Primera mitad (input_1) = 4  -> Decoder genera: 1 << 4
    primera_salida_cifrada = out[0][0]
    decoder_teorico = 1 << 4
    xor_key = primera_salida_cifrada ^ decoder_teorico

    print(f"[+] Clave XOR detectada automáticamente: {xor_key} (binario: {xor_key:016b})")

    flag = []
    for index, (o1, o2) in enumerate(out):
        # Deshacemos el XOR para obtener la salida limpia del decoder
        dec1 = o1 ^ xor_key
        dec2 = o2 ^ xor_key

        # .bit_length() nos dice la posición del bit más alto de forma segura.
        # Restamos 1 porque las posiciones en VHDL empiezan en 0 (ej: 16 es 10000, bit_length=5 -> posición 4)
        bit_alto = dec1.bit_length() - 1 if dec1 > 0 else 0
        bit_bajo = dec2.bit_length() - 1 if dec2 > 0 else 0

        # Validamos que los datos tengan sentido (máximo 4 bits por sección)
        if bit_alto > 15 or bit_bajo > 15:
            print(f"[!] Advertencia: Datos corruptos en la línea {index + 1}")
            continue

        # Reconstruimos el carácter de 8 bits
        caracter_ascii = (bit_alto << 4) | bit_bajo
        flag.append(chr(caracter_ascii))

    print(f"[+] Flag resuelta: {''.join(flag)}")

if __name__ == '__main__':
    solve_vhdlock()
