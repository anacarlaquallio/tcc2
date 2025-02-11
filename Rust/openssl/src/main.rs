extern crate openssl;

use openssl::rsa::{Rsa, Padding};
use std::time::Instant;
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

// Função para calcular a média
fn mean(times: &Vec<f64>) -> f64 {
    let sum: f64 = times.iter().sum();
    sum / times.len() as f64
}

// Função para calcular o desvio padrão
fn standard_deviation(times: &Vec<f64>, mean: f64) -> f64 {
    let variance: f64 = times.iter().map(|value| {
        let diff = mean - (*value as f64);
        diff * diff
    }).sum::<f64>() / times.len() as f64;

    variance.sqrt()
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

fn main() {
    let bits = 4096;
    let iterations_list = vec![10, 100, 1000, 100000]; // Diferentes números de iterações

    let rsa_private = load_private_key("private_2048.pem");
    let rsa_public = load_public_key("public_2048.pem");

    let message = vec![0u8; 190];

    for &iterations in &iterations_list {
        let mut encrypt_times = Vec::new();
        let mut decrypt_times = Vec::new();

        for _ in 0..iterations {
            let start = Instant::now();
            let enc_data = encrypt_message(&rsa_public, &message);
            let duration = start.elapsed();
            encrypt_times.push(duration.as_secs_f64() * 1000.0);

            let start = Instant::now();
            let _dec_data = decrypt_message(&rsa_private, &enc_data);
            let duration = start.elapsed();
            decrypt_times.push(duration.as_secs_f64() * 1000.0);
        }

        let mean_encrypt = mean(&encrypt_times);
        let stddev_encrypt = standard_deviation(&encrypt_times, mean_encrypt);

        let mean_decrypt = mean(&decrypt_times);
        let stddev_decrypt = standard_deviation(&decrypt_times, mean_decrypt);

        println!("\nNúmero de iterações: {}", iterations);
        println!("Cifração:");
        println!("Tempo médio: {:.6} ms", mean_encrypt);
        println!("Desvio padrão: {:.6} ms", stddev_encrypt);

        println!("\nDecifração:");
        println!("Tempo médio: {:.6} ms", mean_decrypt);
        println!("Desvio padrão: {:.6} ms", stddev_decrypt);
    }

}
