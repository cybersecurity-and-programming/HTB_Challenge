#!/usr/bin/python3
def main():
    local_a8 = [
        0x6f722f5c645d4b57,
        0x794066732c6b2c73,
        0x406c6c2c732c732e,
        0x732e6b6c406b6a7d,
        0x6b7c2c6b2c7b4073,
        0x2c737d2b,
        0x62
    ]

    flag = ''.join(
        chr(b ^ 0x1f)
        for pack in local_a8
        for b in pack.to_bytes((pack.bit_length() + 7) // 8, 'big')[::-1]
    )

    print(flag)

if __name__ == '__main__':
    main()
