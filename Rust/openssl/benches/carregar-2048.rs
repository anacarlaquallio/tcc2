extern crate openssl;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use openssl::rsa::{Padding, Rsa};
use std::fs::File;
use std::io::Read;

// Função para carregar a chave pública de um arquivo PEM
fn load_public_key(filename: &str) -> Rsa<openssl::pkey::Public> {
    let mut file = File::open(filename).expect("Falha ao abrir o arquivo de chave pública");
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)
        .expect("Falha ao ler a chave pública");
    Rsa::public_key_from_pem(&pem).expect("Falha ao carregar a chave pública")
}

// Função para carregar a chave privada de um arquivo PEM
fn load_private_key(filename: &str) -> Rsa<openssl::pkey::Private> {
    let mut file = File::open(filename).expect("Falha ao abrir o arquivo de chave privada");
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)
        .expect("Falha ao ler a chave privada");
    Rsa::private_key_from_pem(&pem).expect("Falha ao carregar a chave privada")
}

// Função de cifração
fn encrypt_message(rsa: &Rsa<openssl::pkey::Public>, message: &[u8]) -> Vec<u8> {
    let mut encrypted_data = vec![0; rsa.size() as usize];
    rsa.public_encrypt(message, &mut encrypted_data, Padding::PKCS1)
        .expect("Erro na cifração");
    encrypted_data
}

// Função de decifração
fn decrypt_message(rsa: &Rsa<openssl::pkey::Private>, enc_data: &[u8]) -> Vec<u8> {
    let mut dec_data = vec![0; rsa.size() as usize];
    rsa.private_decrypt(enc_data, &mut dec_data, Padding::PKCS1)
        .expect("Falha na decifração");
    dec_data
}

// Benchmark para geração de chaves
fn benchmark_generation_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate Keys");
    for iteration in [1] {
        group.bench_with_input(
            BenchmarkId::from_parameter(iteration),
            &iteration,
            |b, &_iteration| {
                b.iter(|| Rsa::generate(2048).expect("Falha ao gerar a chave RSA"));
            },
        );
    }
    group.finish();
}

// Benchmark para cifração
fn benchmark_encrypt(c: &mut Criterion) {
    if !std::path::Path::new("public_2048.pem").exists() {
        eprintln!("Chave pública não encontrada, não é possível continuar o benchmark.");
        return;
    }

    let rsa = load_public_key("public_2048.pem");

    let mut file = File::open("message.txt").expect("Falha ao abrir o arquivo de mensagem");
    let mut message = Vec::new();
    file.read_to_end(&mut message)
        .expect("Falha ao ler a mensagem");

    let mut group = c.benchmark_group("Encrypt");

    for size in [10, 100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| encrypt_message(&rsa, &message));
        });
    }

    group.finish();
}

// Benchmark para decifração
fn benchmark_decrypt(c: &mut Criterion) {
    if !std::path::Path::new("private_2048.pem").exists() {
        eprintln!("Chave privada não encontrada, não é possível continuar o benchmark.");
        return;
    }

    let rsa_private = load_private_key("private_2048.pem");
    let rsa_public = load_public_key("public_2048.pem");

    let mut file = File::open("message.txt").expect("Falha ao abrir o arquivo de mensagem");
    let mut message = Vec::new();
    file.read_to_end(&mut message)
        .expect("Falha ao ler a mensagem");

    let enc_data = encrypt_message(&rsa_public, &message);

    let mut group = c.benchmark_group("Decrypt");

    for size in [10, 100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| decrypt_message(&rsa_private, &enc_data));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_generation_keys,
    benchmark_encrypt,
    benchmark_decrypt
);
criterion_main!(benches);