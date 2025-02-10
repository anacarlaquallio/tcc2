#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <iostream>

// Função para gerar o par de chaves RSA
std::unique_ptr<Botan::Private_Key> generate_keypair(const size_t bits, Botan::RandomNumberGenerator &rng)
{
    return std::make_unique<Botan::RSA_PrivateKey>(rng, bits);
}

int main()
{
    // Mensagem a ser criptografada
    std::string plaintext =
        "Your great-grandfather gave this watch to your granddad for good luck. "
        "Unfortunately, Dane's luck wasn't as good as his old man's.";
    std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());

    // Inicializa o gerador de números aleatórios
    Botan::AutoSeeded_RNG rng;

    // Gera o par de chaves RSA
    auto privkey = generate_keypair(2048, rng);
    auto pubkey = privkey->public_key(); // Aqui obtém-se a chave pública como um unique_ptr

    Botan::PK_Encryptor_EME enc(*pubkey, rng, "OAEP(SHA-256)");
    std::vector<uint8_t> ct = enc.encrypt(pt, rng);

    // decrypt with sk
    Botan::PK_Decryptor_EME dec(*privkey, rng, "OAEP(SHA-256)");
    Botan::secure_vector<uint8_t> pt2 = dec.decrypt(ct);

    std::cout << "\nenc: " << Botan::hex_encode(ct) << "\ndec: " << std::string(pt2.begin(), pt2.end()) << std::endl;
    return 0;
}
