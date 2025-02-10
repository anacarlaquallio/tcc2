import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# Teste de geração de chaves RSA
@pytest.mark.parametrize("key_size", [2048, 4096])
def test_key_generation(benchmark, key_size):
    def generate_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    
    # Mede o tempo necessário para gerar a chave
    result = benchmark.pedantic(generate_key, rounds=15)
    
    # Verifica se a chave foi gerada corretamente
    assert result is not None
