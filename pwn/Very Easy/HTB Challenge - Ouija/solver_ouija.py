from binascii import unhexlify

def reverse():
    '''
            00101461 bf 01 00        MOV        EDI,0x1
                    00 00
            00101466 e8 15 fc        CALL       <EXTERNAL>::sleep                                uint sleep(uint __seconds)
                    ff ff
    '''
    MOV_EDI_1 = unhexlify('bf01000000')
    '''
            00101549 bf 0a 00        MOV        EDI,0xa
                    00 00
            0010154e e8 2d fb        CALL       <EXTERNAL>::sleep                                uint sleep(uint __seconds)
                    ff ff
    '''
    MOV_EDI_10 = unhexlify('bf0a000000')
    MOV_EDI_0 = unhexlify('bf00000000')
    with open('ouija', 'rb') as f:
        orig = f.read()
    with open('patched', 'wb') as f :
        f.write(orig.replace(MOV_EDI_1, MOV_EDI_0).replace(MOV_EDI_10, MOV_EDI_0))

if __name__ == '__main__':
    reverse()