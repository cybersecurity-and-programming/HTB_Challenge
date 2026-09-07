import base64
import binascii
import logging
from Crypto.Cipher import AES
from scapy.all import *

aes_key_base64 = "a1E4MUtycWswTmtrMHdqdg=="
aes_key = base64.b64decode(aes_key_base64)

def validate_aes_key(key: bytes):
    """
    Verifica que la clave AES tenga un tamaño válido.

    AES solo admite claves de:
    - 16 bytes (AES-128)
    - 24 bytes (AES-192)
    - 32 bytes (AES-256)

    Esta validación es esencial para evitar errores silenciosos
    durante el descifrado y para asegurar que la clave extraída
    de un artefacto forense es coherente.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(
            f"Clave AES inválida ({len(key)} bytes). "
            "Debe ser de 16, 24 o 32 bytes."
        )

def extract_iv_and_ciphertext(full_data: bytes, iv: bytes = None):
    """
    Extrae el IV (vector de inicialización) y el ciphertext para AES-CBC.

    Esta función soporta dos modos:
    - Modo 1: El IV se pasa explícitamente como argumento.
    - Modo 2: El IV está embebido en los primeros 16 bytes del ciphertext.

    Validaciones importantes:
    - Si el IV se pasa manualmente, debe medir exactamente 16 bytes.
    - Si el IV está embebido, el buffer debe tener al menos 16 bytes.
    - El ciphertext restante debe ser múltiplo del tamaño de bloque AES.

    Esto es crucial en análisis forense, donde los artefactos pueden estar
    truncados, dañados o manipulados, y necesitamos detectar inconsistencias.
    """

    # Caso 1: El IV se proporciona externamente
    if iv is not None:
        if len(iv) != AES.block_size:
            raise ValueError("El IV debe tener exactamente 16 bytes")
        # En este modo, todo el buffer es ciphertext
        return iv, full_data

    # Caso 2: El IV está embebido en los primeros 16 bytes
    if len(full_data) < AES.block_size:
        raise ValueError("El ciphertext es demasiado corto: falta el IV")

    extracted_iv = full_data[:AES.block_size]
    ciphertext = full_data[AES.block_size:]

    # Validar que el ciphertext sea múltiplo del tamaño de bloque AES
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("El ciphertext no es múltiplo del tamaño de bloque AES")

    return extracted_iv, ciphertext

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Descifra un bloque de datos usando AES en modo CBC.

    Parámetros:
    - ciphertext: datos cifrados (múltiplo de 16 bytes)
    - key: clave AES validada previamente
    - iv: vector de inicialización de 16 bytes

    Esta función asume que:
    - El IV y la clave ya han sido validados.
    - El ciphertext tiene un tamaño correcto.
    - No realiza unpad; solo descifra el bloque tal cual.

    Mantener esta función simple y aislada facilita el análisis
    forense, ya que permite inspeccionar el resultado bruto antes
    de aplicar el padding.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def unpad_zero(data: bytes) -> bytes:
    return data.rstrip(b"\x00")

def process_pcap(filename: str, src: str, dst: str, key: bytes) -> None:
    validate_aes_key(key)

    output = ""  # acumulador de hex strings

    with PcapReader(filename) as pcap:
        for pkt in pcap:
            if not pkt.haslayer(DNS):
                continue

            try:
                if pkt[IP].src != dst:
                    continue

                # Extraer el fragmento de datos del dominio
                data = pkt[DNS][DNSQR].qname.decode().split(".")[0]

                if data == "start":
                    output = ""
                    continue

                if data == "end":
                    try:
                        raw = binascii.unhexlify(output)
                        iv, ct = extract_iv_and_ciphertext(raw)
                        decrypted = decrypt_aes_cbc(ct, key, iv)
                        print(unpad_zero(decrypted).decode())
                    except Exception as e:
                        print(f"[ERROR] Fallo al descifrar bloque: {e}")
                    finally:
                        output = ""
                    continue

                # Acumular fragmentos hex
                output += data

            except (UnicodeDecodeError, AttributeError, IndexError) as e:
                print(f"[WARN] Paquete DNS malformado: {e}")

            except binascii.Error as e:
                print(f"[WARN] Hex inválido en fragmento: {e}")
            except ValueError as e:
                print(f"[WARN] Error criptográfico: {e}")

def main():
    process_pcap(
        filename="capture.pcap",
        src="10.0.2.15",
        dst="147.182.172.189",
        key=aes_key
    )

if __name__ == '__main__':
    main()
