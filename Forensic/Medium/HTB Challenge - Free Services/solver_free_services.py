#!/usr/bin/python3
def load_numbers(path: str) -> list[int]:
    """
    Lee el archivo y devuelve la lista de enteros procesados.
    """
    try:
        with open(path, 'r') as f:
            raw = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"No se encontró el archivo: {path}")
    except PermissionError:
        raise PermissionError(f"Permiso denegado al intentar leer: {path}")

    try:
        cleaned = raw.replace("\n", ",").replace("\t", "")
        parts = [x for x in cleaned.split(",") if x]
        return [int(x) for x in parts]
    except ValueError as e:
        raise ValueError(f"Error convirtiendo a entero. Datos corruptos: {e}")


def decode_numbers(nums: list[int], key: int) -> bytes:
    """Aplica XOR a los valores y genera el binario resultante."""
    if not nums:
        raise ValueError("La lista de números está vacía. No hay nada que decodificar.")

    output = bytearray()

    try:
        for i in range(0, len(nums) - 1, 2):
            value = nums[i] ^ key

            if value < 256:
                output.append(value)
            else:
                output += value.to_bytes(2, 'big')

        return bytes(output)

    except OverflowError:
        raise OverflowError(f"El valor {value} no cabe en 2 bytes.")
    except Exception as e:
        raise RuntimeError(f"Error inesperado durante la decodificación: {e}")


def save_binary(path: str, data: bytes) -> None:
    """Guarda los bytes en un archivo binario."""
    try:
        with open(path, 'wb') as f:
            f.write(data)
    except PermissionError:
        raise PermissionError(f"Permiso denegado al escribir en: {path}")
    except OSError as e:
        raise OSError(f"Error al escribir el archivo binario: {e}")


def main():
    input_file = "data.txt"
    output_file = "shellcode.bin"
    key = 24

    try:
        nums = load_numbers(input_file)
        decoded = decode_numbers(nums, key)
        save_binary(output_file, decoded)
        print(f"[+] Decodificación completada. Guardado en: {output_file}")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
