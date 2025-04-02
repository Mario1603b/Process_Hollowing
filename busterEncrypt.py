import base64

# Leer el shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = bytearray(f.read())

# XOR con clave dinámica (0x55)
key = 0x55
encrypted_shellcode = bytearray([b ^ key for b in shellcode])

# Codificar en Base64
encoded_shellcode = base64.b64encode(encrypted_shellcode).decode()

# Guardarlo en un archivo para subirlo al servidor
with open("shellcode_encoded.txt", "w") as f:
    f.write(encoded_shellcode)

print("[+] Shellcode encriptado y guardado en shellcode_encoded.txt")
