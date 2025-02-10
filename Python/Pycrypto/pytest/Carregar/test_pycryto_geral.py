import pytest
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Carregar mensagem
def load_message_from_file(file_path):
    with open(file_path, "rb") as file:
        message = file.read(90)
    return message

# Função para carregar as chaves públicas e privadas
def load_keys(public_key_path, private_key_path):
    with open(public_key_path, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    with open(private_key_path, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    return private_key, public_key

# Teste de cifração
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_encrypt(benchmark, iterations):
    _, public_key = load_keys("public_2048.pem", "private_2048.pem")
    message = load_message_from_file("message.txt")
    
    cipher_rsa = PKCS1_OAEP.new(public_key)

    def _encrypt():
        return cipher_rsa.encrypt(message)

    result = benchmark.pedantic(_encrypt, iterations=iterations, rounds=15)
    assert result is not None

# Teste de decifração
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_decrypt(benchmark, iterations):
    private_key, public_key = load_keys("public_2048.pem", "private_2048.pem")
    message = load_message_from_file("message.txt")
    cipher_rsa = PKCS1_OAEP.new(private_key)
    ciphertext = cipher_rsa.encrypt(message)

    cipher_rsa = PKCS1_OAEP.new(private_key)

    def _decrypt():
        return cipher_rsa.decrypt(ciphertext)

    result = benchmark.pedantic(_decrypt, iterations=iterations, rounds=15)
    assert result is not None