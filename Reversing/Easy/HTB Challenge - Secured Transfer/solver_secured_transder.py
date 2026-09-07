from argparse import ArgumentParser
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from scapy.all import PcapReader

def decrypt(pcap_file):
    # Clave e IV estáticos
    key = b"supersecretkeyusedforencryption!"
    iv = b"someinitialvalue"
    
    # PcapReader procesa el archivo eficientemente paquete por paquete
    with PcapReader(pcap_file) as packets:
        for pkt in packets:
            # Comprobación rápida usando operadores 'in' nativos de Scapy
            if 'TCP' in pkt and 'Raw' in pkt:
                datapkt = pkt['Raw'].load
                if not datapkt:
                    continue
                
                try:
                    # El objeto AES en modo CBC tiene estado interno, 
                    # creamos uno nuevo por cada paquete de datos a descifrar
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher.decrypt(datapkt), AES.block_size)
                    print(decrypted_data.decode('utf-8', errors='replace'))
                except (ValueError, KeyError) as e:
                    pass

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Archivo de paquetes .pcap", required=True)
    opciones = parser.parse_args()
    decrypt(opciones.file)
