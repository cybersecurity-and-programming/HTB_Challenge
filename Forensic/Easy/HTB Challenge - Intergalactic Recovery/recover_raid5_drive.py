#!/usr/bin/python3
def xor(disk1: bytes, disk2: bytes) -> bytes:
    return b"".join([bytes([i^b]) for i, b in zip(disk1, disk2)])

def xor_buffers(d1: bytes, d2: bytes) -> bytes:
    out = bytearray(len(d1))
    for i, (a, b) in enumerate(zip(d1, d2)):
        out[i] = a ^ b
    return bytes(out)

def main():
    try:
        with open("disk1.img", 'rb') as f:
            dist1 = f.read()

        with open("disk2.img", 'rb') as f:
            dist2 = f.read()
    except OSError as e:
        logging.error(f"Error al leer : ' {e}")

    dist3 = xor_buffers(dist1, dist2)
    try:
        with open('./disk3.img', 'wb') as f:
            f.write(dist3)
    except OSError as e:
        print(f"Error guardando archivo: {e}")
if __name__ == '__main__':
    main()
