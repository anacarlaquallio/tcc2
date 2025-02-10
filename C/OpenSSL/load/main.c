#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <time.h>
#include <math.h>

#define MESSAGE_SIZE 90

// Função para carregar a chave pública
EVP_PKEY *load_public_key(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        perror("Erro ao abrir chave pública");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        fprintf(stderr, "Erro ao ler chave pública\n");
    }

    return pkey;
}

// Função para carregar a chave privada
EVP_PKEY *load_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        perror("Erro ao abrir chave privada");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        fprintf(stderr, "Erro ao ler chave privada\n");
    }

    return pkey;
}
// Função para carregar mensagem
int load_message_from_file(const char *filename, unsigned char *message, int max_length)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Erro ao abrir o arquivo para leitura");
        return -1;
    }
    int length = fread(message, sizeof(unsigned char), max_length, file);
    fclose(file);
    return length;
}

// Função para geração das chaves
void generate_keys()
{
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (pkey == NULL)
    {
        fprintf(stderr, "error: rsa gen\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    FILE *fp = fopen("public.pem", "wt");
    if (fp != NULL)
    {
        PEM_write_PUBKEY(fp, pkey);
        fclose(fp);
    }
    else
    {
        perror("file error");
    }

    fp = fopen("private.pem", "wt");
    if (fp != NULL)
    {
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
    }
    else
    {
        perror("file error");
    }

    EVP_PKEY_free(pkey);
}

// Função de cifração
unsigned char *encrypt(unsigned char *src, unsigned int len, int *length, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    unsigned char *dst = (unsigned char *)malloc(2048);
    size_t outl;
    if (!EVP_PKEY_encrypt(ctx, dst, &outl, src, (size_t)len))
    {
        fprintf(stderr, "Erro na cifragem\n");
        EVP_PKEY_CTX_free(ctx);
        free(dst);
        return NULL;
    }
    *length = outl;
    EVP_PKEY_CTX_free(ctx);
    return dst;
}

// Função de decifração
unsigned char *decrypt(unsigned char *src, int len, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    unsigned char *dst = NULL;
    size_t outl;

    if (EVP_PKEY_decrypt(ctx, NULL, &outl, src, len) <= 0)
    {
        fprintf(stderr, "Erro na decifragem\n");
    }
    else
    {
        dst = (unsigned char *)malloc(outl);
        if (!dst)
        {
            fprintf(stderr, "Falha ao alocar memória\n");
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }

        if (EVP_PKEY_decrypt(ctx, dst, &outl, src, len) <= 0)
        {
            fprintf(stderr, "Erro na decifragem\n");
            free(dst);
            dst = NULL;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return dst;
}

// Função para calcular a média
double calcular_media(double tempos[], int n)
{
    double soma = 0.0;
    for (int i = 0; i < n; i++)
    {
        soma += tempos[i];
    }
    return soma / n;
}

// Função para calcular o desvio padrão
double calcular_desvio_padrao(double tempos[], int n, double media)
{
    double soma = 0.0;
    for (int i = 0; i < n; i++)
    {
        soma += pow(tempos[i] - media, 2);
    }
    return sqrt(soma / n);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Uso: %s <nome_do_arquivo_json>\n", argv[0]);
        return 1;
    }

    const char *json_filename = argv[1];

    unsigned char message[MESSAGE_SIZE];

    // Lista de iterações
    int iteration_counts[] = {10, 100, 1000, 10000};
    int num_iteration_sets = sizeof(iteration_counts) / sizeof(iteration_counts[0]);

    // Medir o tempo de geração de chaves
    clock_t start = clock();
    generate_keys();
    clock_t end = clock();
    double tempo_geracao = ((double)(end - start)) / CLOCKS_PER_SEC;

    EVP_PKEY *public_key = load_public_key("public_2048.pem");
    EVP_PKEY *private_key = load_private_key("private_2048.pem");

    if (public_key == NULL || private_key == NULL)
    {
        fprintf(stderr, "Erro ao carregar chaves. O programa será finalizado.\n");
        return 1;
    }

    int message_length = load_message_from_file("message.txt", message, MESSAGE_SIZE);

    if (message_length <= 0)
    {
        fprintf(stderr, "Erro ao carregar a mensagem do arquivo\n");
        return 1;
    }

    FILE *json_file = fopen(json_filename, "w");
    if (json_file == NULL)
    {
        perror("Erro ao criar arquivo JSON");
        return 1;
    }

    fprintf(json_file, "{\n  \"results\": [\n");

    // Processar para cada conjunto de iterações
    for (int set = 0; set < num_iteration_sets; set++)
    {
        int iterations = iteration_counts[set];
        double tempos_cifracao[iterations];
        double tempos_decifracao[iterations];

        for (int i = 0; i < iterations; i++)
        {
            int ciphertext_len;
            clock_t start = clock();
            unsigned char *ciphertext = encrypt(message, MESSAGE_SIZE, &ciphertext_len, public_key);
            clock_t end = clock();
            tempos_cifracao[i] = ((double)(end - start)) / CLOCKS_PER_SEC;

            start = clock();
            unsigned char *decrypted_message = decrypt(ciphertext, ciphertext_len, private_key);
            end = clock();
            tempos_decifracao[i] = ((double)(end - start)) / CLOCKS_PER_SEC;

            free(ciphertext);
            free(decrypted_message);
        }

        double media_cifracao = calcular_media(tempos_cifracao, iterations);
        double desvio_cifracao = calcular_desvio_padrao(tempos_cifracao, iterations, media_cifracao);

        double media_decifracao = calcular_media(tempos_decifracao, iterations);
        double desvio_decifracao = calcular_desvio_padrao(tempos_decifracao, iterations, media_decifracao);

        // Escrever os resultados para este conjunto de iterações no JSON
        fprintf(json_file, "    {\n");
        fprintf(json_file, "      \"iterations\": %d,\n", iterations);
        fprintf(json_file, "      \"encryption\": {\n");
        fprintf(json_file, "        \"mean\": %.15f,\n", media_cifracao);
        fprintf(json_file, "        \"stddev\": %.15f\n", desvio_cifracao);
        fprintf(json_file, "      },\n");
        fprintf(json_file, "      \"decryption\": {\n");
        fprintf(json_file, "        \"mean\": %.15f,\n", media_decifracao);
        fprintf(json_file, "        \"stddev\": %.15f\n", desvio_decifracao);
        fprintf(json_file, "      }\n");
        fprintf(json_file, "    }%s\n", (set < num_iteration_sets - 1) ? "," : "");
    }

    fprintf(json_file, "  ]\n}\n");
    fclose(json_file);

    printf("Resultados salvos em %s\n", json_filename);
    printf("Tempo de geração de chaves: %.6f segundos\n", tempo_geracao);

    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    return 0;
}