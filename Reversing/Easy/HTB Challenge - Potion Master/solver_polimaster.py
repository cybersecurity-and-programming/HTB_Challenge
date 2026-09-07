from z3 import BitVec, Solver, sat
from functools import reduce
import operator

def decrypt():
    a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, 17, 11, -56, 61, -74, 52, 63, -21, 53, -17, 66, -10, -58, 0]  # Debe tener 38 elementos (76 / 2)
    b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 93, 59, 106, 43, 30, 47, 93, 62, 97, 63] # Debe tener 26 elementos (76 / 3 redondeado hacia arriba)
    c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 396, 333, 320, 380, 362, 368, 286]  # Debe tener 19 elementos (76 / 4)
    d = [52, 52, 95, 95, 110, 49, 51, 51, 95, 110, 110, 53, 116, 51, 98, 63]  # Debe tener 16 elementos (76 / 5 redondeado hacia arriba)

    s = Solver()
    flag = [BitVec(f"flag_{i}", 8) for i in range(76)]

    # Restricciones de caracteres imprimibles ASCII
    for i in range(len(flag)):
        s.add(flag[i] > 0x20)
        s.add(flag[i] < 0x7f)

    # Condición A (Paso 2)
    for i in range(0, 76, 2):
        s.add(flag[i] - flag[i+1] == a[i//2])

    # Condición B (Paso 3)
    for i in range(0, 76, 3):
        # reduce aplica XOR incluso si el último grupo tiene menos de 3 elementos
        s.add(reduce(operator.xor, flag[i:i+3], 0) == b[i//3])

    # Condición C (Paso 4)
    for i in range(0, 76, 4):
        s.add(sum(flag[i:i+4]) == c[i//4])

    # Condición D (Paso 5)
    for i in range(0, 76, 5):
        s.add(flag[i] == d[i//5])

    # Verificación y extracción del resultado
    if s.check() == sat:
        m = s.model()
        # Usamos .as_long() para convertir el objeto Z3 a un entero de Python
        resultado = bytes([m[f].as_long() for f in flag]).decode()
        print(f"Flag encontrada: HTB{{{resultado}}}")
    else:
        print("No se encontró solución (unsat). Revisa si las restricciones o los arreglos a, b, c, d son correctos.")

if __name__== '__main__':
    decrypt()

'''
for i in range(0, 76, 2):
    s.add(reduce(lambda x, y: x - y, x[i : i + 2]) == a[i // 2])

for i in range(0, 76, 3):
    s.add(reduce(lambda x, y: x ^ y, x[i : i + 3]) == b[i // 3])

for i in range(0, 76, 4):
    s.add(reduce(lambda x, y: x + y, x[i : i + 4]) == c[i // 4])

for i in range(0, 76, 5):
    s.add(x[i] == d[i // 5])

for i in range(76):
    s.add(x[i] <= 0x7f)
    s.add(0x20 <= x[i])

s.check()
model = s.model()

flag = ''.join(chr(model[i].as_long()) for i in x)

print('HTB{' + flag + '}')
'''
