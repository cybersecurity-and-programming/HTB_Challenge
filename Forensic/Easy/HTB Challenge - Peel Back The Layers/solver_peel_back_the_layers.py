from pwn import p64

vals = [
    0x33725f317b425448,
    0x6b316c5f796c6c34,
    0x706d343374735f33,
    0x306230725f6b6e75,
    0x0d0a7d2121217374
]

flag = b"".join(p64(v) for v in vals)
print(flag.decode())
