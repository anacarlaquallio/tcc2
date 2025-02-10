#include <iostream>
#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iomanip>

#define ITERATIONS 10000 
#define MESSAGE_SIZE 460 

using namespace CryptoPP;

// https://www.cryptopp.com/wiki/Linux#Build_and_Install_the_Library
CryptoPP::AutoSeededRandomPool rng;

std::vector<uint8_t> generate_random_message(size_t size)
{
    std::vector<uint8_t> message(size);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(message.data(), size);
    return message;
}

void generateKeys()
{
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 4096);

    RSA::PublicKey publicKey(privateKey);

    std::ofstream privateFile("private.key", std::ios::binary);
    CryptoPP::FileSink privateSink(privateFile);
    privateKey.DEREncode(privateSink);
    privateFile.close();

    std::ofstream publicFile("public.key", std::ios::binary);
    CryptoPP::FileSink publicSink(publicFile);
    publicKey.DEREncode(publicSink);
    publicFile.close();
}

RSA::PublicKey load_public_key(const std::string &filename)
{
    RSA::PublicKey publicKey;
    FileSource file(filename.c_str(), true);
    publicKey.BERDecode(file);
    return publicKey;
}

RSA::PrivateKey load_private_key(const std::string &filename)
{
    RSA::PrivateKey privateKey;
    FileSource file(filename.c_str(), true);
    privateKey.BERDecode(file);
    return privateKey;
}

std::string encrypt(std::string encrypt)
{

    CryptoPP::RSA::PublicKey publicKey;
    std::ifstream publicFile("public.key", std::ios::binary);
    CryptoPP::FileSource publicSource(publicFile, true);
    publicKey.BERDecode(publicSource);
    publicFile.close();

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    std::string ciphered;
    CryptoPP::StringSource(encrypt, true, new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(ciphered)));

    std::string encoded_ciphered;
    CryptoPP::StringSource(ciphered, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded_ciphered)));
    return encoded_ciphered;
}

std::string decrypt(std::string decrypt)
{

    CryptoPP::RSA::PrivateKey privateKey;
    std::ifstream privateFile("private.key", std::ios::binary);
    CryptoPP::FileSource privateSource(privateFile, true);
    privateKey.BERDecode(privateSource);
    privateFile.close();

    std::string decoded_ciphered;
    CryptoPP::StringSource(decrypt, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_ciphered)));

    std::string recovered;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    CryptoPP::StringSource(decoded_ciphered, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(recovered)));
    return recovered;
}

double calcular_media(const std::vector<double> &tempos)
{
    double soma = 0.0;
    for (double tempo : tempos)
    {
        soma += tempo;
    }
    return soma / tempos.size();
}

double calcular_desvio_padrao(const std::vector<double> &tempos, double media)
{
    double soma = 0.0;
    for (double tempo : tempos)
    {
        soma += std::pow(tempo - media, 2);
    }
    return std::sqrt(soma / tempos.size());
}

int main()
{
    std::vector<double> tempos_cifracao(ITERATIONS);
    std::vector<double> tempos_decifracao(ITERATIONS);

    RSA::PublicKey publicKey = load_public_key("public.key");
    RSA::PrivateKey privateKey = load_private_key("private.key");

    std::vector<byte> randomMessageVector = generate_random_message(MESSAGE_SIZE);

    std::string randomMessage(reinterpret_cast<const char *>(randomMessageVector.data()), randomMessageVector.size());

    for (int i = 0; i < ITERATIONS; i++)
    {
        auto start = std::chrono::high_resolution_clock::now();
        std::string cipherText = encrypt(randomMessage);
        auto end = std::chrono::high_resolution_clock::now();
        tempos_cifracao[i] = std::chrono::duration<double>(end - start).count();

        start = std::chrono::high_resolution_clock::now();
        std::string decryptedText = decrypt(cipherText);
        end = std::chrono::high_resolution_clock::now();
        tempos_decifracao[i] = std::chrono::duration<double>(end - start).count();
    }

    double media_cifracao = calcular_media(tempos_cifracao);
    double desvio_cifracao = calcular_desvio_padrao(tempos_cifracao, media_cifracao);

    double media_decifracao = calcular_media(tempos_decifracao);
    double desvio_decifracao = calcular_desvio_padrao(tempos_decifracao, media_decifracao);

    std::cout << std::fixed << std::setprecision(10); // Define 10 casas decimais
    std::cout << "Tempo médio de cifração: " << media_cifracao << " segundos (desvio padrão: " << desvio_cifracao << ")\n";
    std::cout << "Tempo médio de decifração: " << media_decifracao << " segundos (desvio padrão: " << desvio_decifracao << ")\n";

    return 0;
}