from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Offsets onde as partes da chave foram encontradas
offsets = [
    405624, 405640, 405656, 405672, 405688, 405704, 405720, 405736,
    405752, 405768, 405784, 405800, 405816, 405832, 405848, 405864,
    405880, 405896
]

# Tamanho de cada parte
part_size = 16

with open("target.30157", "rb") as f:
    # Ler o conteúdo do arquivo
    dump_data = f.read()

    key_parts = []
    for offset in offsets:
        # Extrair os bytes no offset atual
        part = dump_data[offset:offset + part_size]
        key_parts.append(part)

    # Combinar as partes para reconstruir a chave completa
    full_key = b"".join(key_parts)

    with open("openssl_2048.bin", "wb") as key_file:
        key_file.write(full_key)

    print("Chave completa extraída e salva em 'chave.bin'.")
    print("Tamanho da chave:", len(full_key), "bytes")



