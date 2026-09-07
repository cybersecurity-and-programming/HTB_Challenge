import angr
import claripy
import angr
import claripy

def reverse():
    p = angr.Project("spookylicence")
    inputstr = claripy.BVS('inputstr', 8 * 32)
    state = p.factory.entry_state(args=["./spookylicence", inputstr])

    for byte in inputstr.chop(8):  # Separa los 256 bits en 32 bloques de 8 bits (1 byte)
        state.solver.add(byte >= 0x20)  # Espacio en blanco (inicio de caracteres imprimibles)
        state.solver.add(byte <= 0x7E)  # Tilde ~ (fin de caracteres imprimibles)

    simgr = p.factory.simulation_manager(state)
    print("[*] Explorando caminos... Esto puede tomar unos momentos.")
    simgr.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1) or b"Incorrect" in s.posix.dumps(1)
    )

    if simgr.found:
        f = simgr.found[0]
        print("\n[+] ¡Camino correcto encontrado!")
        
        stdout_output = f.posix.dumps(1).decode(errors='ignore')
        print(f"STDOUT:\n{stdout_output}")
        
        flag = f.solver.eval(inputstr, cast_to=bytes).decode(errors='ignore')
        print(f"FLAG: {flag.strip()}")
    else:
        print("\n[-] No se encontro ningun camino que cumpla las condiciones.")
        print("Prueba revisando si el texto de 'find' o 'avoid' coincide exactamente con el del binario.")

if __name__ == '__main__':
    reverse()