#include <stdio.h>
#include <gcrypt.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>

#define MESSAGE_SIZE 190

// Função auxiliar para mostrar erros
static void die(const char *format, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, format);
    vfprintf(stderr, format, arg_ptr);
    va_end(arg_ptr);
    if (*format && format[strlen(format) - 1] != '\n')
    {
        putc('\n', stderr);
    }
    exit(1);
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

// Função para gerar as chaves RSA
void generate_key(gcry_sexp_t *pub_key, gcry_sexp_t *sec_key)
{
    gcry_sexp_t key_spec, key;
    int rc;

    rc = gcry_sexp_new(&key_spec, "(genkey (rsa (nbits 4:2048)))", 0, 1);
    if (rc)
    {
        die("error creating S-expression: %s\n", gcry_strerror(rc));
    }

    rc = gcry_pk_genkey(&key, key_spec);
    gcry_sexp_release(key_spec);
    if (rc)
    {
        die("error generating RSA key: %s\n", gcry_strerror(rc));
    }

    *pub_key = gcry_sexp_find_token(key, "public-key", 0);
    *sec_key = gcry_sexp_find_token(key, "private-key", 0);
    if (!*pub_key || !*sec_key)
    {
        die("Key extraction failed\n");
    }
    gcry_sexp_release(key);
}

// Função para carregar as chaves S-Expression
gcry_sexp_t load_key_from_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("Error opening file");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    char *buffer = gcry_xmalloc(size + 1);
    fread(buffer, 1, size, file);
    buffer[size] = '\0';
    fclose(file);

    gcry_sexp_t key;
    int rc = gcry_sexp_new(&key, buffer, size, 1);
    gcry_free(buffer);

    if (rc)
    {
        die("Error loading key from file: %s\n", gcry_strerror(rc));
    }

    return key;
}

// Função de cifração
gcry_sexp_t encrypt_data(const char *message, gcry_sexp_t pub_key)
{
    gcry_sexp_t plain, cipher;
    int rc;

    rc = gcry_sexp_build(&plain, NULL, "(data (flags raw) (value %b))", MESSAGE_SIZE, message);
    if (rc)
    {
        die("converting data for encryption failed: %s\n", gcry_strerror(rc));
    }

    rc = gcry_pk_encrypt(&cipher, plain, pub_key);
    gcry_sexp_release(plain);
    if (rc)
    {
        die("encryption failed: %s\n", gcry_strerror(rc));
    }

    return cipher;
}

// Função de decifração
void decrypt_data(gcry_sexp_t cipher, gcry_sexp_t sec_key)
{
    gcry_sexp_t plain;
    int rc;

    rc = gcry_pk_decrypt(&plain, cipher, sec_key);
    if (rc)
    {
        die("decryption failed: %s\n", gcry_strerror(rc));
    }

    gcry_sexp_release(plain);
}

// Função para calcular média de tempo
double calcular_media(double tempos[], int n)
{
    double soma = 0.0;
    for (int i = 0; i < n; i++)
    {
        soma += tempos[i];
    }
    return soma / n;
}

// Função para calcular desvio padrão
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

    gcry_sexp_t pub_key, sec_key, cipher;
    char message[MESSAGE_SIZE];

    int iteration_counts[] = {10, 100, 1000, 10000};
    int num_iteration_sets = sizeof(iteration_counts) / sizeof(iteration_counts[0]);

    clock_t start = clock();
    generate_key(&pub_key, &sec_key);
    clock_t end = clock();
    double tempo_geracao =((double)(end - start)) / CLOCKS_PER_SEC;

    pub_key = load_key_from_file("public_2048.txt");
    sec_key = load_key_from_file("private_2048.txt");

    int message_length = load_message_from_file("message.txt", (unsigned char *)message, MESSAGE_SIZE);

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

    for (int set = 0; set < num_iteration_sets; set++)
    {
        int iterations = iteration_counts[set];
        double *tempos_cifracao = malloc(iterations * sizeof(double));
        double *tempos_decifracao = malloc(iterations * sizeof(double));

        if (tempos_cifracao == NULL || tempos_decifracao == NULL)
        {
            perror("Erro ao alocar memória para os tempos");
            return 1;
        }

        for (int i = 0; i < iterations; i++)
        {
            clock_t start = clock();
            cipher = encrypt_data(message, pub_key);
            clock_t end = clock();
            tempos_cifracao[i] = ((double)(end - start)) / CLOCKS_PER_SEC;

            start = clock();
            decrypt_data(cipher, sec_key);
            end = clock();
            tempos_decifracao[i] = ((double)(end - start)) / CLOCKS_PER_SEC;
            gcry_sexp_release(cipher);
        }

        double media_cifracao = calcular_media(tempos_cifracao, iterations);
        double desvio_cifracao = calcular_desvio_padrao(tempos_cifracao, iterations, media_cifracao);

        double media_decifracao = calcular_media(tempos_decifracao, iterations);
        double desvio_decifracao = calcular_desvio_padrao(tempos_decifracao, iterations, media_decifracao);

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

        free(tempos_cifracao);
        free(tempos_decifracao);
    }

    fprintf(json_file, "  ]\n}\n");
    fclose(json_file);

    printf("Resultados salvos em %s\n", json_filename);
    printf("Tempo de geração de chaves: %.6f segundos\n",tempo_geracao);

    gcry_sexp_release(pub_key);
    gcry_sexp_release(sec_key);

    return 0;
}