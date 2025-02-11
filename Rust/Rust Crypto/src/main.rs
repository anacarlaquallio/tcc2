extern crate rsa;

use rand::RngCore;
use std::time::Instant;
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

// Função para calcular a média
fn mean(times: &Vec<f64>) -> f64 {
    let sum: f64 = times.iter().sum();
    sum / times.len() as f64
}

// Função para calcular o desvio padrão
fn standard_deviation(times: &Vec<f64>, mean: f64) -> f64 {
    let variance: f64 = times
        .iter()
        .map(|value| {
            let diff = mean - (*value as f64);
            diff * diff
        })
        .sum::<f64>()
        / times.len() as f64;

    variance.sqrt()
}

fn main() {
    let bits = 4096;
    let mut rng = rand::thread_rng();
    let iterations_list = vec![10, 100, 1000, 10000];

    let pub_key = load_public_key("public_2048.pem").expect("Falha ao carregar a chave pública");
    let priv_key = load_private_key("private_2048.pem").expect("Falha ao carregar a chave privada");

    let mut data = vec![0u8; 190];
    rng.fill_bytes(&mut data);

    let mut encrypt_times = Vec::new();
    let mut decrypt_times = Vec::new();

    for &iterations in &iterations_list {

        for _ in 0..iterations {
            let start = Instant::now();
            let enc_data = pub_key
                .encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])
                .expect("failed to encrypt");
            let duration = start.elapsed();
            encrypt_times.push(duration.as_secs_f64() * 1000.0);

            let start = Instant::now();
            let _dec_data = priv_key
                .decrypt(Pkcs1v15Encrypt, &enc_data)
                .expect("failed to decrypt");
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
