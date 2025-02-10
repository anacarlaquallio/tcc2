const forge = require('node-forge');
const fs = require('fs');
const { performance } = require('perf_hooks');

// Função para carregar a chave pública
const loadPublicKey = (filename) => {
  const pem = fs.readFileSync(filename, 'utf8');
  return forge.pki.publicKeyFromPem(pem);
};

// Função para carregar a chave privada
const loadPrivateKey = (filename) => {
  const pem = fs.readFileSync(filename, 'utf8');
  return forge.pki.privateKeyFromPem(pem);
};

// Função para gerar chave RSA
const generateKeyRSA = () => {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 }, (err, keypair) => {
      if (err) reject(err);
      else resolve({ publicKey: keypair.publicKey, privateKey: keypair.privateKey });
    });
  });
};

// Cifração
const encryptMessage = (publicKey, message) => {
  const encrypted = publicKey.encrypt(forge.util.encodeUtf8(message), 'RSA-OAEP', {
    md: forge.md.sha256.create(),
  });
  return encrypted;
};

// Decifração
const decryptMessage = (privateKey, encryptedMessage) => {
  const decrypted = privateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
    md: forge.md.sha256.create(),
  });
  return forge.util.decodeUtf8(decrypted);
};

// Função para calcular média e desvio padrão
const calculateStats = (times) => {
  const mean = times.reduce((a, b) => a + b) / times.length;
  const variance = times.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / times.length;
  const stddev = Math.sqrt(variance);
  return { mean, stddev };
};

(async () => {
  const iterations = 1000;
  let keyGenerationTime = 0;
  const encryptionTimes = [];
  const decryptionTimes = [];

  const message = forge.util.bytesToHex(forge.random.getBytesSync(90));

    // Carregar as chaves geradas no OpenSSL
    const publicKey = loadPublicKey('public_2048.pem');
    const privateKey = loadPrivateKey('private_2048.pem');

  for (let i = 0; i < iterations; i++) {
    // Medir o tempo de cifração
    const startEncrypt = performance.now();
    const encryptedMessage = encryptMessage(publicKey, message);
    const endEncrypt = performance.now();
    encryptionTimes.push(endEncrypt - startEncrypt);

    // Medir o tempo de decifração
    const startDecrypt = performance.now();
    const decryptedMessage = decryptMessage(privateKey, encryptedMessage);
    const endDecrypt = performance.now();
    decryptionTimes.push(endDecrypt - startDecrypt);
  }

  // Calcular média e desvio padrão para cifração e decifração
  const encryptionStats = calculateStats(encryptionTimes);
  const decryptionStats = calculateStats(decryptionTimes);

  console.log(`Geração de Chaves: ${keyGenerationTime.toFixed(6)} ms`);
  console.log(`Cifração - Tempo médio: ${encryptionStats.mean.toFixed(6)} ms, Desvio padrão: ${encryptionStats.stddev.toFixed(6)} ms`);
  console.log(`Decifração - Tempo médio: ${decryptionStats.mean.toFixed(6)} ms, Desvio padrão: ${decryptionStats.stddev.toFixed(6)} ms`);
})();