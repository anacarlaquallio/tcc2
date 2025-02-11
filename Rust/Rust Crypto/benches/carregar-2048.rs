extern crate rsa;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;

fn load_public_key(file_path: &str) -> Result<RsaPublicKey, Box<dyn Error>> {
    let pem = fs::read_to_string(file_path)?;
    let public_key =
        RsaPublicKey::from_public_key_pem(&pem).expect("Falha ao decodificar a chave pública");
    Ok(public_key)
}

fn load_private_key(file_path: &str) -> Result<RsaPrivateKey, Box<dyn Error>> {
    let pem = fs::read_to_string(file_path)?;
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&pem).expect("Falha ao decodificar a chave privada");
    Ok(private_key)
}

fn encrypt_message(public_key: &RsaPublicKey, message: &[u8], rng: &mut ThreadRng) -> Vec<u8> {
    public_key
        .encrypt(rng, Pkcs1v15Encrypt, message)
        .expect("failed to encrypt")
}

fn decrypt_message(private_key: &RsaPrivateKey, encrypted_data: &[u8]) -> Vec<u8> {
    private_key
        .decrypt(Pkcs1v15Encrypt, encrypted_data)
        .expect("failed to decrypt")
}

// Benchmark para geração de chaves
fn benchmark_generation_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate Keys");
    let mut rng = rand::thread_rng();
    for iteration in [1] {
        group.bench_with_input(
            BenchmarkId::from_parameter(iteration),
            &iteration,
            |b, &_iteration| {
                b.iter(|| {
                    let priv_key =
                        RsaPrivateKey::new(&mut rng, 2048).expect("Falha ao gerar a chave privada");
                    let _pub_key = RsaPublicKey::from(&priv_key);
                });
            },
        );
    }

    group.finish();
}

// Função para o benchmark de cifração
fn benchmark_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();

    let public_key = load_public_key("public_2048.pem").expect("Falha ao carregar a chave pública");

    let mut file = File::open("message.txt").expect("Falha ao abrir o arquivo de mensagem");
    let mut message = Vec::new();
    file.read_to_end(&mut message)
        .expect("Falha ao ler a mensagem");

    let mut group = c.benchmark_group("Encrypt");

    for &_size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(_size), &_size, |b, &_size| {
            b.iter_batched(
                || public_key.clone(), // Organiza o setup da chave para cada iteração
                |public_key| encrypt_message(&public_key, &message, &mut rng),
                criterion::BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

// Função para o benchmark de decifragem
fn benchmark_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();

    let public_key = load_public_key("public_2048.pem").expect("Falha ao carregar a chave pública");
    let private_key = load_private_key("private_2048.pem").expect("Falha ao carregar a chave privada");

    let mut file = File::open("message.txt").expect("Falha ao abrir o arquivo de mensagem");
    let mut message = Vec::new();
    file.read_to_end(&mut message)
        .expect("Falha ao ler a mensagem");

    let encrypted_data = encrypt_message(&public_key, &message, &mut rng); // A cifra é gerada antes do benchmark

    let mut group = c.benchmark_group("Decrypt");

    for &_size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(_size), &_size, |b, &_size| {
            b.iter_batched(
                || private_key.clone(), // Organiza o setup da chave para cada iteração
                |private_key| decrypt_message(&private_key, &encrypted_data),
                criterion::BatchSize::LargeInput,
            );
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
