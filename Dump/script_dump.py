from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

pem_key = "private_2048.pem"

if "PRIVATE" in pem_key:
    key = serialization.load_pem_private_key(
        pem_key.encode(), password=None, backend=default_backend()
    )
else:
    key = serialization.load_pem_public_key(
        pem_key.encode(), backend=default_backend()
    )

# Serializar a chave para o formato DER
der_bytes = key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Chave em bytes:\v", der_bytes)

# Inverter a sequência de bytes
inverted_bytes = der_bytes[::-1]

print("Chave invertida em bytes: \n", inverted_bytes)

hex_key = der_bytes.hex()
print("Chave em hexadecimal:\n", hex_key)

hex_inkey = inverted_bytes.hex()
print("Chave invertida em hexadecimal:\n", hex_inkey)

with open("target.30157", "rb") as f:
    dump_data = f.read()

key_bytes = der_bytes
offset = dump_data.find(key_bytes)

if offset != -1:
    print(f"Chave encontrada no offset: {offset}")
else:
    print("Chave não encontrada no dump.")

offset = dump_data.find(inverted_bytes)

if offset != -1:
    print(f"Chave invertida encontrada no offset: {offset}")
else:
    print("Chave invertida não encontrada no dump.")

part_size = 16
key_parts = [key_bytes[i:i + part_size] for i in range(0, len(key_bytes), part_size)]

# Procurar cada parte no dump
for part in key_parts:
    offset = dump_data.find(part)
    if offset != -1:
        print(f"Parte da chave encontrada no offset: {offset}")
    else:
        print("Parte da chave não encontrada no dump.")