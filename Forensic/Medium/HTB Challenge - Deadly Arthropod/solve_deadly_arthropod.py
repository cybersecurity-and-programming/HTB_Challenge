# Construcción del mapa HID → caracteres
def build_usb_map():
    usb = {}

    """
    # Letras a–z
    for i, c in enumerate("abcdefghijklmnopqrstuvwxyz", start=0x04):
        usb[i] = c + c.upper()

    # Números 1–0
    numbers = "1234567890"
    shifted = "!@#$%^&*()"
    for i, (n, s) in enumerate(zip(numbers, shifted), start=0x1E):
        usb[i] = n + s
    """
    usb.update({
        #Letras
        **{i: c + c.upper() for i, c in enumerate("abcdefghijklmnopqrstuvwxyz", start=0x04)},
        # Números
        **{i: n + s for i, (n, s) in enumerate(zip("1234567890", "!@#$%^&*()"), start=0x1E)},
    })


    # Símbolos y espacio
    usb.update({
        0x2C: " ",
        0x2D: "-_",
        0x2E: "=+",
        0x2F: "[{",
        0x30: "]}",
        0x32: "#~",
        0x33: ";:",
        0x34: "'\"",
        0x36: ",<",
        0x37: ".>",
    })

    # Flechas y control
    usb.update({
        0x4F: "RIGHT",
        0x50: "LEFT",
        0x51: "DOWN",
        0x52: "UP",
        0x28: "ENTER",
        0x2A: "BACK",
    })

    return usb


# Procesa un único evento HID
def process_event(mod, code, lines, pos, col, usb):
    # Movimiento vertical
    if code in (0x28, 0x51):  # ENTER o DOWN
        pos += 1
        col = 0
        return pos, col

    if code == 0x52:  # UP
        pos -= 1
        col = len(lines[pos])
        return pos, col

    # Movimiento horizontal
    if code == 0x50:  # LEFT
        col = max(0, col - 1)
        return pos, col

    if code == 0x4F:  # RIGHT
        col = min(len(lines[pos]), col + 1)
        return pos, col

    # Backspace
    if code == 0x2A:
        if col > 0:
            lines[pos] = lines[pos][:col-1] + lines[pos][col:]
            col -= 1
        return pos, col

    # Caracter imprimible
    if code in usb:
        chars = usb[code]
        char = chars[1] if mod == 2 else chars[0]

        lines[pos] = lines[pos][:col] + char + lines[pos][col:]
        col += 1

    return pos, col


# Función principal que procesa el archivo
def decode_hid_file(path):
    usb = build_usb_map()
    lines = [""] * 50
    pos = 0
    col = 0

    with open(path, "r") as f:
        for raw in f:
            mod = int(raw[0:2], 16)
            code = int(raw[4:6], 16)

            if code == 0:
                continue

            pos, col = process_event(mod, code, lines, pos, col, usb)

    return [l for l in lines if l.strip()]


# -----------------------------
#  EJECUCIÓN
# -----------------------------
if __name__ == "__main__":
    result = decode_hid_file("keys")
    for line in result:
        print(line)
