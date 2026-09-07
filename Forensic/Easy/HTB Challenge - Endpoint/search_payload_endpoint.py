#!/usr/bin/python3
import re
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def main():
    regex = r"INSERT INTO xQGgYA VALUES \('([^']+)'\)"
	try:
        with open('analisis_codigo.txt', 'r') as f:
            content = f.read()

        matches = re.findall(regex, content, re.MULTILINE)
        final_str = "".join(matches)
        print(final_str)
    except FileNotFoundError:
        logging.error("Archivo no encontrado: analisis_codigo.txt")
    except OSError as e:
        logging.error(f"Error al leer el archivo: {e}")

if __name__ == '__main__':
    main()

