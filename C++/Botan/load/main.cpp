#include <botan/x509_key.h>
#include <botan/data_src.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <benchmark/benchmark.h>

#define MESSAGE_SIZE 190

std::unique_ptr<Botan::Private_Key> privkey;
std::unique_ptr<Botan::Public_Key> pubkey;
std::vector<uint8_t> message;
std::vector<uint8_t> cipher;

// Função para carregar as chaves
void load_keys(const std::string &privateKeyPath, const std::string &publicKeyPath)
{
    try
    {
        // Leitura da chave privada
        Botan::DataSource_Stream privateSource(privateKeyPath);
        privkey = Botan::PKCS8::load_key(privateSource);

        // Leitura da chave pública
        Botan::DataSource_Stream publicSource(publicKeyPath);
        pubkey = Botan::X509::load_key(publicSource);
    }
    catch (const Botan::Exception &e)
    {
        std::cerr << "Erro ao carregar as chaves: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

// Função para geração de chaves RSA
std::unique_ptr<Botan::Private_Key> generate_keypair(const size_t bits, Botan::RandomNumberGenerator &rng)
{
    return std::make_unique<Botan::RSA_PrivateKey>(rng, bits);
}

// Função para carregar mensagem
std::vector<uint8_t> load_message_from_file(const std::string &file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo: " + file_path);
    }

    // Ler conteúdo do arquivo
    std::vector<uint8_t> message((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return message;
}

// Função benchmark para geração de chaves
static void BM_GenerateKeys(benchmark::State &state)
{
    Botan::AutoSeeded_RNG rng;

    double tempo_geracao;

    for (auto _ : state)
    {
        auto generate = generate_keypair(2048, rng);
        benchmark::DoNotOptimize(cipher); // Impede otimizações excessivas
    }
}

// Função benchmark para cifração
static void BM_EncryptMessage(benchmark::State &state)
{
    Botan::AutoSeeded_RNG rng;
    Botan::PK_Encryptor_EME enc(*pubkey, rng, "OAEP(SHA-256)");

    for (auto _ : state)
    {
        cipher = enc.encrypt(message.data(), message.size(), rng);
        benchmark::DoNotOptimize(cipher); // Impede otimizações excessivas
    }
}

// Função benchmark para decifração
static void BM_DecryptMessage(benchmark::State &state)
{
    Botan::AutoSeeded_RNG rng;
    Botan::PK_Decryptor_EME dec(*privkey, rng, "OAEP(SHA-256)");

    for (auto _ : state)
    {
        Botan::secure_vector<uint8_t> decrypted = dec.decrypt(cipher);
        benchmark::DoNotOptimize(decrypted); // Impede otimizações excessivas
    }
}

// Registrar benchmarks
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
    // Caminhos para os arquivos PEM
    const std::string privateKeyPath = "private_2048.pem";
    const std::string publicKeyPath = "public_2048.pem";

    load_keys(privateKeyPath, publicKeyPath);

    message = load_message_from_file("message.txt");

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    return 0;
}
