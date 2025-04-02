shellcode = open("shellcode.bin", "rb").read()
encrypted_shellcode = bytearray([b ^ 0x55 for b in shellcode])

with open("shellcode_encrypted.bin", "wb") as f:
    f.write(encrypted_shellcode)
