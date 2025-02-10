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

// Função para carregar a mensagem 
const loadMessage = (filename) => {
  return fs.readFileSync(filename, 'utf8').trim();
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

// Função de cifração
const encryptMessage = (publicKey, message) => {
  const encrypted = publicKey.encrypt(forge.util.encodeUtf8(message), 'RSA-OAEP', {
    md: forge.md.sha256.create(),
  });
  return encrypted;
};

// Função de decifração
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
  const args = process.argv.slice(2);
  const outputFileName = args[0]; 
  if (!outputFileName) {
    console.error('Erro: Por favor, forneça o nome do arquivo JSON como argumento.');
    process.exit(1);
  }

  const iterationsList = [10, 100, 1000, 10000];
  const results = []; 
  try {
    const startKeyGen = performance.now();
    const { publicKeyG, privateKeyG } = await generateKeyRSA();
    const endKeyGen = performance.now();
    const keyGenerationTime = endKeyGen - startKeyGen;

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
