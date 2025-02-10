#include <stdio.h>
#include <gcrypt.h>
#include <string.h>

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

static void show_sexp(const char *prefix, gcry_sexp_t a)
{
    char *buf;
    size_t size;

    if (prefix)
        fputs(prefix, stderr);
    size = gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = gcry_xmalloc(size);

    gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, buf, size);
    fprintf(stderr, "%.*s", (int)size, buf);
    gcry_free(buf);
}

int main()
{
    gcry_sexp_t key_spec, key, pub_key, sec_key;
    int rc;
    size_t len;
    gcry_sexp_t cipher, l;
    gcry_sexp_t plain;
    const char *mensagem_original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";;

    //-------------------------------------------------------------------
    // Generate Key
    //-------------------------------------------------------------------
    rc = gcry_sexp_new(&key_spec, "(genkey (rsa (nbits 4:2048)))", 0, 1);
    if (rc)
    {
        die("error creating S-expression: %s\n", gcry_strerror(rc));
    }
    //>> Generate key
    rc = gcry_pk_genkey(&key, key_spec);
    gcry_sexp_release(key_spec);
    if (rc)
    {
        die("error generating RSA key: %s\n", gcry_strerror(rc));
    }
    show_sexp("generated RSA key:\n", key);

    //>> Extract parts
    pub_key = gcry_sexp_find_token(key, "public-key", 0);
    if (!pub_key)
    {
        die("public part missing in key\n");
    }

    sec_key = gcry_sexp_find_token(key, "private-key", 0);
    if (!sec_key)
    {
        die("private part missing in key\n");
    }

    //-------------------------------------------------------------------
    // Encrypt Data
    //-------------------------------------------------------------------
    //>> Create plain text.
    rc = gcry_sexp_build(&plain, NULL, "(data (flags pkcs1) (value %s))", mensagem_original);
    if (rc)
    {
        die("converting data for encryption failed: %s\n", gcry_strerror(rc));
    }

    //>> Encrypt data.
    rc = gcry_pk_encrypt(&cipher, plain, pub_key);
    if (rc)
    {
        die("encryption failed: %s\n", gcry_strerror(rc));
    }

    //-------------------------------------------------------------------
    // Extract value
    //-------------------------------------------------------------------
    show_sexp("Encrypted data:\n", cipher);
    l = gcry_sexp_find_token(cipher, "a", 0);

    const char *data = gcry_sexp_nth_data(l, 1, &len);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", (unsigned char)data[i]);
    }
    printf("\n");

    //-------------------------------------------------------------------
    // Decrypt Data
    //-------------------------------------------------------------------
    rc = gcry_pk_decrypt(&plain, cipher, sec_key);
    if (rc)
    {
        die("decryption failed: %s\n", gcry_strerror(rc));
    }

    printf("Decrypted data:\n");
    show_sexp(NULL, plain);

    return 0;
}
