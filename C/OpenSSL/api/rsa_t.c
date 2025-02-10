#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-RSA.html
// https://www.openssl.org/docs/manmaster/man3/EVP_RSA_gen.html
void generateKeys()
{
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (pkey == NULL)
    {
        fprintf(stderr, "error: rsa gen\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    FILE *fp = fopen("public.key", "wt");
    if (fp != NULL)
    {
        PEM_write_PUBKEY(fp, pkey);
        fclose(fp);
    }
    else
    {
        perror("file error");
    }
    fp = fopen("private.key", "wt");
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

// https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt.html
unsigned char *encrypt(unsigned char *src, unsigned int len, int *length)
{
    FILE *fp = fopen("public.key", "r");
    if (fp == NULL)
    {
        perror("file error");
        return NULL;
    }
    EVP_PKEY *pkey;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL)
    {
        fprintf(stderr, "error: read publics key\n");
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    unsigned char *dst = (unsigned char *)malloc(2048);
    size_t outl;
    if (!EVP_PKEY_encrypt(ctx, dst, &outl, src, (size_t)len))
    {
        fprintf(stderr, "error: encrypt\n");
        EVP_PKEY_free(pkey);
        free(dst);
        return NULL;
    }
    int len2 = outl;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    BIO_dump_fp(stdout, dst, len2);
    printf("len: %d, len2: %d\n", len, len2);
    if (length != NULL)
    {
        *length = len2;
    }
    return dst;
}

// https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html
unsigned char *decrypt(unsigned char *src, int len)
{
    FILE *fp = fopen("private.key", "r");
    if (fp == NULL)
    {
        perror("file error");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        fprintf(stderr, "error: read private key\n");
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    unsigned char *dst = NULL;
    size_t outl;
    size_t inl = len;

    if (EVP_PKEY_decrypt(ctx, NULL, &outl, src, inl) <= 0)
    {
        fprintf(stderr, "error: decrypt\n");
    }
    else
    {
        dst = (unsigned char *)malloc(outl);
        if (!dst)
        {
            fprintf(stderr, "malloc failure\n");
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }

        if (EVP_PKEY_decrypt(ctx, dst, &outl, src, inl) <= 0)
        {
            fprintf(stderr, "error: decrypt\n");
            free(dst);
            dst = NULL;
        }
        else
        {
            BIO_dump_fp(stdout, dst, (int)outl);
            printf("len: %d, outl: %zu\n", len, outl);
        }
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return dst;
}

int main()
{
    generateKeys();

    // Mensagem a ser criptografada
    unsigned char mensagem[] = "Hello, RSA!";
    int mensagem_len = strlen((const char *)mensagem);

    printf("Mensagem original: %s\n", mensagem);

    // Criptografar a mensagem
    int ciphertext_len;
    unsigned char *ciphertext = encrypt(mensagem, mensagem_len, &ciphertext_len);

    // Se a criptografia falhar, encerrar
    if (ciphertext == NULL)
    {
        fprintf(stderr, "Falha ao criptografar a mensagem\n");
        return 1;
    }

    // Imprimir a mensagem criptografada
    printf("Mensagem criptografada:\n");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Descriptografar a mensagem
    unsigned char *decrypted_message = decrypt(ciphertext, ciphertext_len);

    // Se a descriptografia falhar, encerrar
    if (decrypted_message == NULL)
    {
        fprintf(stderr, "Falha ao descriptografar a mensagem\n");
        return 1;
    }

    // Imprimir a mensagem descriptografada
    printf("Mensagem descriptografada: %s\n", decrypted_message);

    // Liberar memória alocada
    free(ciphertext);
    free(decrypted_message);

    return 0;
}
