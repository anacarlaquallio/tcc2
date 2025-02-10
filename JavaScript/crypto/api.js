const crypto = require('crypto');
const fs = require('fs');
const { performance } = require('perf_hooks');

// Função para carregar a chave pública
const loadPublicKey = (filename) => {
    return fs.readFileSync(filename, 'utf8');
};

// Função para carregar a chave privada
const loadPrivateKey = (filename) => {
    return fs.readFileSync(filename, 'utf8');
};

// Função para gerar chave RSA
const generateKeyRSA = () => {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        }, (err, publicKey, privateKey) => {
            if (err) reject(err);
            else resolve({ publicKey, privateKey });
        });
    });
};

// Função de cifração
const encryptMessage = (publicKey, message) => {
    const buffer = Buffer.from(message, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted;
};

// Função de decifração
const decryptMessage = (privateKey, encryptedMessage) => {
    const decrypted = crypto.privateDecrypt(privateKey, encryptedMessage);
    return decrypted.toString('utf8');
};

// Função para calcular média e desvio padrão
const calculateStats = (times) => {
    const mean = times.reduce((a, b) => a + b) / times.length;
    const variance = times.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / times.length;
    const stddev = Math.sqrt(variance);
    return { mean, stddev };
};

(async () => {
    const iterations = 10000; 
    let keyGenerationTime = 0;
    const encryptionTimes = [];
    const decryptionTimes = [];

    const message = crypto.randomBytes(90);

    const publicKey = loadPublicKey("public_2048.pem");
    const privateKey = loadPrivateKey("private_2048.pem");

    for (let i = 0; i < iterations; i++) {
        const startEncrypt = performance.now();
        const encryptedMessage = encryptMessage(publicKey, message);
        const endEncrypt = performance.now();
        encryptionTimes.push(endEncrypt - startEncrypt);

        const startDecrypt = performance.now();
        const decryptedMessage = decryptMessage(privateKey, encryptedMessage);
        const endDecrypt = performance.now();
        decryptionTimes.push(endDecrypt - startDecrypt);
    }

    const encryptionStats = calculateStats(encryptionTimes);
    const decryptionStats = calculateStats(decryptionTimes);

    console.log(`Geração de Chaves: ${keyGenerationTime.toFixed(6)} ms`);
    console.log(`Cifração - Tempo médio: ${encryptionStats.mean.toFixed(2)} ms, Desvio padrão: ${encryptionStats.stddev.toFixed(2)} ms`);
    console.log(`Decifração - Tempo médio: ${decryptionStats.mean.toFixed(2)} ms, Desvio padrão: ${decryptionStats.stddev.toFixed(2)} ms`);
})();
