#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <benchmark/benchmark.h>
#include <fstream>

#define MESSAGE_SIZE 190 // Tamanho da mensagem aleatória

using namespace CryptoPP;

RSA::PublicKey publicKey;
RSA::PrivateKey privateKey;
std::vector<uint8_t> randomMessageVector;
std::string randomMessage;
std::string cipherText;

// Carregar mensagem
std::vector<uint8_t> load_message_from_file(const std::string &file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo: " + file_path);
    }

    std::vector<uint8_t> message((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return message;
}

// Função de geração de chaves
void generateKeys()
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

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

// Função para carregar chave pública de um arquivo
RSA::PublicKey load_public_key(const std::string &filename)
{
    RSA::PublicKey publicKey;
    FileSource file(filename.c_str(), true);
    publicKey.BERDecode(file);
    return publicKey;
}

// Função para carregar chave privada de um arquivo
RSA::PrivateKey load_private_key(const std::string &filename)
{
    RSA::PrivateKey privateKey;
    FileSource file(filename.c_str(), true);
    privateKey.BERDecode(file);
    return privateKey;
}

// Função de cifração
std::string encrypt_message(const std::string &message, const RSA::PublicKey &publicKey)
{
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    std::string cipherText;
    StringSource(message, true,
                 new PK_EncryptorFilter(rng, encryptor,
                                        new StringSink(cipherText)));

    return cipherText;
}

// Função de decifração
std::string decrypt_message(const std::string &cipherText, const RSA::PrivateKey &privateKey)
{
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    std::string recoveredText;
    StringSource(cipherText, true,
                 new PK_DecryptorFilter(rng, decryptor,
                                        new StringSink(recoveredText)));

    return recoveredText;
}

// Função benchmark para geração de chaves
static void BM_GenerateKeys(benchmark::State &state)
{
    // Benchmark
    for (auto _ : state)
    {
        generateKeys();
        benchmark::DoNotOptimize(cipherText); // Impede otimizações excessivas
    }
}

// Função benchmark para cifração
static void BM_EncryptMessage(benchmark::State &state)
{

    // Benchmark
    for (auto _ : state)
    {
        cipherText = encrypt_message(randomMessage, publicKey);
        benchmark::DoNotOptimize(cipherText); // Impede otimizações excessivas
    }
}

// Função benchmark para decifração
static void BM_DecryptMessage(benchmark::State &state)
{
    for (auto _ : state)
    {
        std::string decryptedText = decrypt_message(cipherText, privateKey);
        benchmark::DoNotOptimize(decryptedText); // Impede otimizações excessivas
    }
}

BENCHMARK(BM_GenerateKeys)->Iterations(1)->Repetitions(5);
BENCHMARK(BM_EncryptMessage)->Iterations(10)->Repetitions(5);
BENCHMARK(BM_DecryptMessage)->Iterations(10)->Repetitions(5);
BENCHMARK(BM_EncryptMessage)->Iterations(100)->Repetitions(5);
BENCHMARK(BM_DecryptMessage)->Iterations(100)->Repetitions(5);
BENCHMARK(BM_EncryptMessage)->Iterations(1000)->Repetitions(5);
BENCHMARK(BM_DecryptMessage)->Iterations(1000)->Repetitions(5);
BENCHMARK(BM_EncryptMessage)->Iterations(10000)->Repetitions(5);
BENCHMARK(BM_DecryptMessage)->Iterations(10000)->Repetitions(5);

int main(int argc, char **argv)
{
    publicKey = load_public_key("public_2048.der");
    privateKey = load_private_key("private_2048.der");

    randomMessageVector = load_message_from_file("message.txt");
    randomMessage = std::string(reinterpret_cast<const char *>(randomMessageVector.data()), randomMessageVector.size());

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    return 0;
}
