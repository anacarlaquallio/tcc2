package org.sample;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Timestamp;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1)
@State(Scope.Thread)
public class Carregar {

    @Param({"10", "100", "1000", "10000"})
    private int iterations;
    private RSAPrivateCrtKeyParameters privateKey;
    private RSAKeyParameters publicKey;
    private String plainMessage;
    private String encryptedMessageDecrypt;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        this.privateKey = loadPrivateKey("private_2048.pem");
        this.publicKey = loadPublicKey("public_2048.pem");
        this.plainMessage = loadMessageFromFile("message.txt");
        this.encryptedMessageDecrypt = Encrypt(plainMessage.getBytes("UTF-8"), publicKey);
    }

    // Benchmark para geração de chaves
    @Benchmark
    public AsymmetricCipherKeyPair testGenerateKeys() throws Exception {
        return GenerateKeys();
    }

    // Benchmark para cifração
    @Benchmark
    public String testEncrypt() throws Exception {
        return Encrypt(plainMessage.getBytes("UTF-8"), publicKey);
    }

    // Benchmark para decifração
    @Benchmark
    public String testDecrypt() throws Exception {
        return Decrypt(encryptedMessageDecrypt, privateKey);
    }

    public static String getHexString(byte[] b) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : b) {
            result.append(Integer.toString((value & 0xff) + 0x100, 16).substring(1));
        }
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void GetTimestamp(String info) {
        System.out.println(info + new Timestamp((new Date()).getTime()));
    }

    // Função de geração de chaves
    public static AsymmetricCipherKeyPair GenerateKeys() throws NoSuchAlgorithmException {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
                new BigInteger("10001", 16), // publicExponent
                SecureRandom.getInstance("SHA1PRNG"), // pseudorandom number generator
                2048, // strength
                80 // certainty
        ));

        return generator.generateKeyPair();
    }

    // Função para carregar chave pública
    public static RSAKeyParameters loadPublicKey(String filePath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(filePath))) {
            Object object = pemParser.readObject();
            if (object instanceof SubjectPublicKeyInfo) {
                SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) object;
                RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());
                return new RSAKeyParameters(false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
            } else {
                throw new IllegalArgumentException("Arquivo PEM não contém uma chave pública válida.");
            }
        }
    }

    // Função para carregar chave privada
    public static RSAPrivateCrtKeyParameters loadPrivateKey(String filePath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(filePath))) {
            Object object = pemParser.readObject();
            if (object instanceof PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
                return new RSAPrivateCrtKeyParameters(
                        rsaPrivateKey.getModulus(),
                        rsaPrivateKey.getPublicExponent(),
                        rsaPrivateKey.getPrivateExponent(),
                        rsaPrivateKey.getPrime1(),
                        rsaPrivateKey.getPrime2(),
                        rsaPrivateKey.getExponent1(),
                        rsaPrivateKey.getExponent2(),
                        rsaPrivateKey.getCoefficient()
                );
            } else {
                throw new IllegalArgumentException("Arquivo PEM não contém uma chave privada válida.");
            }
        }
    }

    // Função para carregar mensagem
    public static String loadMessageFromFile(String filePath) throws IOException {
        StringBuilder message = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                message.append(line).append("\n");
            }
        }
        if (message.length() > 0) {
            message.setLength(message.length() - 1);
        }
        return message.toString();
    }

    // Função de cifração
    public static String Encrypt(byte[] data, AsymmetricKeyParameter publicKey) throws Exception {
        RSAEngine engine = new RSAEngine();
        engine.init(true, publicKey);
        byte[] hexEncodedCipher = engine.processBlock(data, 0, data.length);
        return getHexString(hexEncodedCipher);
    }

    // Função de decifração
    public static String Decrypt(String encrypted, AsymmetricKeyParameter privateKey)
            throws InvalidCipherTextException {
        AsymmetricBlockCipher engine = new RSAEngine();
        engine.init(false, privateKey);
        byte[] encryptedBytes = hexStringToByteArray(encrypted);
        byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);
        return new String(hexEncodedCipher);
    }

}
