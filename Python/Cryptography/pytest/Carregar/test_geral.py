import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Carregar chaves
def load_keys(public_key_path, private_key_path):
    with open(public_key_path, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())
    
    with open(private_key_path, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
    
    return private_key, public_key

# Carregar mensagem de arquivo txt
def load_message_from_file(file_path):
    with open(file_path, "rb") as file:
        message = file.read(90)  # Ajuste se necessário
    return message

# Geração de chaves
def generate_keys(key_sizes):
    rsa_keys = {}
    for key_size in key_sizes:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        rsa_keys[key_size] = (private_key, public_key)
    return rsa_keys

# Teste de geração de chaves
@pytest.mark.parametrize("iterations", [1])
def test_generationKeys(benchmark, iterations):
    def _generation():
        return generate_keys([2048])
        
    result = benchmark.pedantic(_generation, iterations=iterations, rounds=15)
    assert result is not None

# Teste de cifração
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_encrypt(benchmark, iterations):
    _, public_key = load_keys("public_2048.pem", "private_2048.pem")
    message = load_message_from_file("message.txt")
    
    def _encrypt():
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    result = benchmark.pedantic(_encrypt, iterations=iterations, rounds=15)
    assert result is not None

# Teste de decifração
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_decrypt(benchmark, iterations):
    private_key, public_key = load_keys("public_2048.pem", "private_2048.pem")
    message = load_message_from_file("message.txt")
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    def _decrypt():
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    result = benchmark.pedantic(_decrypt, iterations=iterations, rounds=15)
    assert result is not None
