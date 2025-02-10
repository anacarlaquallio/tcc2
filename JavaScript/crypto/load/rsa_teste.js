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

// Função para carregar a mensagem
const loadMessage = (filename) => {
    return fs.readFileSync(filename, 'utf8').trim();
};

// Função para gerar chave RSA
const generateKeyRSA = () => {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 2048,
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

// Função para cifração
const encryptMessage = (publicKey, message) => {
    const buffer = Buffer.from(message, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted;
};

// Função para decifração
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

    const args = process.argv.slice(2); // Obtém argumentos da linha de comando
    const outputFileName = args[0]; // Nome do arquivo de saída deve ser o primeiro argumento
    if (!outputFileName) {
      console.error('Erro: Por favor, forneça o nome do arquivo JSON como argumento.');
      process.exit(1);
    }

    const iterationsList = [10, 100, 1000, 10000]; // Lista de números de iterações
    const results = []; // Para armazenar os resultados

    try {
        const startKeyGen = performance.now();
        const { publicKeyG, privateKeyG } = await generateKeyRSA();
        const endKeyGen = performance.now();
        keyGenerationTime = endKeyGen - startKeyGen;


            results.push({
                generateKeys: {
                    mean: keyGenerationTime.toFixed(6),
                },
            });

        fs.writeFileSync(outputFileName, JSON.stringify(results, null, 2));
        console.log(`Resultados salvos em "${outputFileName}".`);
    } catch (error) {
        console.error('Erro durante o processamento:', error.message);
    }
})();