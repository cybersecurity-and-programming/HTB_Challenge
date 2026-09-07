import base64
import binascii
import logging
from Crypto.Cipher import AES

logging.basicConfig(level=logging.INFO, format='[AES] %(message)s')
aes_key_base64 = "a1E4MUtycWswTmtrMHdqdg=="
aes_key = base64.b64decode(aes_key_base64)

def decode_base64(data: str) -> bytes:
    """
    Decodifica una cadena Base64 y valida su formato.

    - Acepta str o bytes.
    - Lanza TypeError si el tipo no es válido.
    - Lanza ValueError si el contenido no es Base64 correcto.

    Esta función es útil en análisis forense porque evita
    procesar datos corruptos o manipulados.
    """
    if not isinstance(data, (str, bytes)):
        raise TypeError("El ciphertext debe ser una cadena Base64")

    try:
        return base64.b64decode(data)
    except binascii.Error:
        # Error típico cuando el Base64 está truncado o manipulado
        raise ValueError("El ciphertext no es Base64 válido")


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


def unpad_zero(data: bytes) -> bytes:
    return data.rstrip(b"\x00")

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

def decrypt_message(ciphertext_b64: str, key: bytes, iv: bytes = None) -> str:
    """
    Función de alto nivel que coordina todo el proceso de descifrado.

    Flujo completo:
    1. Validar la clave AES.
    2. Decodificar el ciphertext desde Base64.
    3. Extraer IV + ciphertext (o usar IV externo si se proporciona).
    4. Registrar información útil para análisis forense (IV y tamaño).
    5. Descifrar usando AES-CBC.
    6. Eliminar padding PKCS7.
    7. Devolver el resultado como texto UTF-8.

    Esta función es la interfaz principal del módulo y está diseñada
    para ser robusta, clara y segura en escenarios forenses donde
    los datos pueden estar incompletos, corruptos o manipulados.
    """
    validate_aes_key(key)

    # Decodificar Base64 → bytes
    full_data = decode_base64(ciphertext_b64)

    # Extraer IV y ciphertext (o usar IV externo)
    iv, ciphertext = extract_iv_and_ciphertext(full_data, iv)

    # Descifrado bruto
    decrypted = decrypt_aes_cbc(ciphertext, key, iv)

    # Convertir a texto legible
    return unpad_zero(decrypted).decode("utf-8", errors="replace")

def main():
    try:
        with open("texto_encriptado.txt", 'r') as f:
            data = f.readlines()
    except ValueError:
        logging.error(f"Clave AES inválida: {clave_aes}")
        return
    except FileNotFoundError:
        logging.error(f"Archivo no encontrado: {file}")
        return
    except OSError as e:
        logging.error(f"Error al leer: {e}")
        return

    for encrypted_base64 in data:
        decrypted_text = decrypt_message(encrypted_base64, aes_key)
        print(decrypted_text)

if __name__ == '__main__':
    main()
