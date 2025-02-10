import pytest
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Configuração das chaves RSA
@pytest.fixture
def rsa_keys():
    keys = [2048, 4096]
    rsa_keys = {}
    for key_size in keys:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        rsa_keys[key_size] = (private_key, public_key)
    return rsa_keys

# Teste de cifração
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_encrypt(benchmark, rsa_keys, key_size, iterations):
    private_key, public_key = rsa_keys[key_size]
    message = os.urandom(190)
    
    def _encrypt():
        return public_key.encrypt(message, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    
    result = benchmark.pedantic(_encrypt, iterations=iterations, rounds=15)
    assert result is not None

