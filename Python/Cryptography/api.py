import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Esse código baseia-se na documentação da biblioteca Cryptography
# Disponível em: https://cryptography.io/
# Com base nesse código, o processo de microbenchmarking foi gerado

# Gerar um par de chaves RSA: e = 65537 e k = 2048
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048)

# Obter a chave pública a partir da chave privada
public_key = private_key.public_key()

# Tamanho limite 190 bytes
message = os.urandom(190) #limite porque ainda vai fazer padding
#message = b"My message"

# Cifrar a mensagem com a chave pública
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#ciphertext = public_key.encrypt(
#    message,
#    padding.PKCS1v15()  # Esquema de padding
#)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#plaintext = private_key.decrypt(
#    ciphertext,
#    padding.PKCS1v15()  # Esquema de padding
#)

# Converter as chaves para representações em bytes
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Exibir as chaves e a mensagem original
print("Chave privada:\n", private_pem.decode())
print("\nChave pública:\n", public_pem.decode())
print("\nMensagem original (hexadecimal):\n", message.hex())
print("\nMensagem decifrada (hexadecimal):\n", plaintext.hex())