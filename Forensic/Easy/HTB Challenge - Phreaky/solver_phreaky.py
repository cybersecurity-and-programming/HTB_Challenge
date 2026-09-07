#!/usr/bin/python3
from argparse import ArgumentParser
from scapy.all import sniff, TCP
from scapy.error import Scapy_Exception
from base64 import b64decode
from zipfile import ZipFile, BadZipFile
from PyPDF2 import PdfReader
from PyPDF2.errors import PdfReadError
import signal, sys, os, logging, re, binascii
from base64 import b64decode

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def exit_handler(sig, frame) -> None:
    """
    Manejador para Ctrl+C que garantiza una salida limpia.
    """
    logging.info("Interrupción recibida, cerrando la aplicación…")
    sys.exit(1)

signal.signal(signal.SIGINT, exit_handler)

BANNER = r"""
██████╗ ██╗  ██╗██████╗ ███████╗ █████╗ ██╗  ██╗██╗   ██╗
██╔══██╗██║  ██║██╔══██╗██╔════╝██╔══██╗██║ ██╔╝╚██╗ ██╔╝
██████╔╝███████║██████╔╝█████╗  ███████║█████╔╝  ╚████╔╝
██╔═══╝ ██╔══██║██╔══██╗██╔══╝  ██╔══██║██╔═██╗   ╚██╔╝
██║     ██║  ██║██║  ██║███████╗██║  ██║██║  ██╗   ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

            HTB CHALLENGE - P H R E A K Y
"""
def print_banner():
    print(BANNER)

def extract_tcp_stream(pcap_file: str, output_file: str, target_port_str: str) -> bool:
    """
    Extrae el flujo TCP asociado a un puerto concreto desde un archivo PCAP.

    Este método no reconstruye sesiones ni reordena paquetes; simplemente
    concatena los payloads tal y como aparecen en el PCAP. Para análisis
    de ciertos payloads es suficiente porque el canal es secuencial.

    Args:
        pcap_file (str): Ruta al archivo PCAP.
        output_file (str): Archivo donde se guardará el stream crudo.
        target_port (int): Puerto TCP usado por el payload.

    Returns:
        None. Escribe el resultado en disco.
    """

    # Validación temprana del puerto
    try:
        target_port = int(target_port_str)
    except ValueError:
        logging.error(f"El puerto debe ser un número entero: {target_port_str}")
        return False

    if target_port <= 0:
        logging.error(f"Puerto inválido: {target_port}")
        return False

    # Validación del archivo PCAP
    if not os.path.isfile(pcap_file):
        logging.error(f"El archivo PCAP no existe: {pcap_file}")
        return False

    tcp_stream = bytearray()

    def get_stream(pkt) -> None:
        """
        Callback interno para procesar cada paquete del PCAP.
        """
        if not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]

        # Filtramos por puerto origen/destino
        if target_port not in (tcp.sport, tcp.dport):
            return

        payload = bytes(tcp.payload)
        if payload:
            tcp_stream.extend(payload)

    # Procesar el PCAP
    try:
        sniff(offline=pcap_file, prn=get_stream, store=False)
    except FileNotFoundError:
        logging.error(f"No se pudo abrir el archivo PCAP: {pcap_file}")
        return False
    except Scapy_Exception as e:
        logging.error(f"Error al procesar el PCAP (Scapy): {e}")
        return False
    except OSError as e:
        logging.error(f"Error de E/S al leer el PCAP: {e}")
        return False

    if len(tcp_stream) == 0:
        logging.warning("No se encontró tráfico en el puerto especificado.")
        return False

    # Guardar el resultado
    try:
        with open(output_file, 'wb') as f:
            f.write(tcp_stream)
    except PermissionError:
        logging.error(f"Permiso denegado al escribir en '{output_file}'")
        return False
    except FileNotFoundError:
        logging.error(f"Ruta inválida para '{output_file}'")
        return False
    except OSError as e:
        logging.error(f"Error de E/S al escribir '{output_file}': {e}")
        return False

    logging.info(f"Flujo TCP reconstruido: {len(tcp_stream)} bytes escritos en '{output_file}'")
    return True

def parse_stream(output_file: str) -> bytes:
    """
    Procesa el stream reconstruido, extrae adjuntos ZIP, los descifra
    y devuelve los bytes concatenados del PDF final.
    """
    flag_pdf_bytes = b""

    try:
        with open(output_file, 'rb') as f:
            raw = f.read()
        data = raw.decode('utf-8', errors='ignore')
    except FileNotFoundError:
        logging.error(f"Archivo no encontrado: {output_file}")
        return b""
    except OSError as e:
        logging.error(f"Error leyendo el archivo '{output_file}': {e}")
        return b""

    # Buscar bloque válido
    match = re.search(r"Secure File Transfer.*?Content-Type: multipart/mixed;(.*)", data, re.DOTALL)

    if not match:
        logging.error("No se encontró un bloque válido de transferencia segura con multipart/mixed")
        return b""

    parts = match.group(1).split("Content-Type:")[1:]
    password = None

    for part in parts:
        if 'Password' in part:
            password = part.split('Password:')[1].split('\r\n\r\n')[0].strip()

        if 'Content-Disposition: attachment;' in part:
            try:
                filename = part.split('filename*1="')[1].split('.zip"')[0] + '.zip'
                attachment = part.split('\r\n\r\n')[1].replace('\r\n', '').strip()
            except Exception as e:
                logging.error(f"Error parseando metadatos del adjunto: {e}")
                continue

            # Guardar ZIP
            try:
                with open(filename, 'wb') as outfile:
                    outfile.write(b64decode(attachment))
            except binascii.Error as e:
                logging.error(f"Error decodificando Base64 del adjunto {filename}: {e}")
                continue
            except OSError as e:
                logging.error(f"Error escribiendo ZIP '{filename}': {e}")
                continue

            # Extraer ZIP
            try:
                with ZipFile(filename) as zf:
                    zip_out = zf.infolist()[0].filename
                    zf.extractall(pwd=password.encode())
                    logging.info(f"ZIP extraído: {filename} -> {zip_out}")
            except BadZipFile as e:
                logging.error(f"ZIP corrupto '{filename}': {e}")
                continue
            except RuntimeError as e:
                logging.error(f"Contraseña incorrecta para ZIP '{filename}': {e}")
                continue

            # Leer PDF parcial
            try:
                with open(zip_out, 'rb') as pdf_part:
                    flag_pdf_bytes += pdf_part.read()
            except OSError as e:
                logging.error(f"Error leyendo PDF parcial '{zip_out}': {e}")
                continue

    return flag_pdf_bytes

def save_pdf(pdf_bytes: bytes, output_path: str) -> bool:
    try:
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
        logging.info(f"PDF final guardado en: {output_path}")
        return True
    except OSError as e:
        logging.error(f"Error guardando PDF final '{output_path}': {e}")
        return False

def read_pdf(path: str) -> str:
    try:
        reader = PdfReader(path)
    except FileNotFoundError:
        logging.error(f"No se encontró el PDF final: {path}")
        return ""
    except PdfReadError as e:
        logging.error(f"El PDF está corrupto o no se puede leer: {e}")
        return ""
    except OSError as e:
        logging.error(f"Error del sistema al abrir el PDF '{path}': {e}")
        return ""

    pdf_text = ""

    for idx, page in enumerate(reader.pages):
        try:
            extracted = page.extract_text()
            if extracted:
                pdf_text += extracted
        except KeyError as e:
            logging.warning(f"Página {idx}: estructura interna inesperada ({e})")
        except ValueError as e:
            logging.warning(f"Página {idx}: contenido inválido ({e})")
        except TypeError as e:
            logging.warning(f"Página {idx}: extract_text devolvió un tipo inesperado ({e})")
        except Exception as e:
            logging.warning(f"Página {idx}: error desconocido ({e})")

    return pdf_text

def extract_flag(pdf_text: str) -> str | None:
    try:
        for line in pdf_text.split('\n'):
            if 'HTB{' in line:
                return 'HTB' + line.split('HTB')[1].split('}')[0] + '}'
    except (IndexError, ValueError, TypeError) as e:
        logging.error(f"Error analizando texto del PDF: {e}")
        return None

    return None

def analizar_stream_data(output_file: str) -> None:
    pdf_bytes = parse_stream(output_file)
    if not pdf_bytes:
        logging.error("No se pudo reconstruir el PDF final.")
        return

    if not save_pdf(pdf_bytes, "flag.pdf"):
        return

    pdf_text = read_pdf("flag.pdf")
    if not pdf_text:
        logging.error("No se pudo extraer texto del PDF.")
        return

    flag = extract_flag(pdf_text)
    if flag:
        logging.info(f"Flag encontrada: {flag}")
    else:
        logging.warning("No se encontró ninguna flag en el PDF.")


if __name__ == '__main__':
    parser = ArgumentParser(
        description="Herramienta forense para analizar tráfico del challenge de HTB"
    )
    parser.add_argument("-f", "--files", help="Archivo PCAP a analizar", required=True)
    parser.add_argument("-o", "--output", help="Archivo resultante del análisis de PCAP", required=True)
    parser.add_argument("-p", "--port", help="Puerto del tráfico a analizar", required=True)
    args = parser.parse_args()

    output = args.output

    print_banner()

    resultado = extract_tcp_stream(args.files, args.output, args.port)
    if resultado == True:
        analizar_stream_data(output)
