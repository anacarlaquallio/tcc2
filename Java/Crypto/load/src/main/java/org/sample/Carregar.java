package org.sample;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Param;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1)
@State(Scope.Thread)
public class Carregar {

    @Param({"10", "100", "1000", "10000"})
    private int iterations;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String plainMessage;
    private byte[] encryptedMessageDecrypt;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        this.privateKey = loadPrivateKey("private_2048.pem");
        this.publicKey = loadPublicKey("public_2048.pem");
        this.plainMessage = loadMessageFromFile("message.txt");
        this.encryptedMessageDecrypt = encrypt(plainMessage.getBytes("UTF-8"), publicKey);
    }

    // Benchmark de geração de chaves
    @Benchmark
    public KeyPair testGenerationKeys() throws Exception {
        return generateKeyPair();
    }

    // Benchmark para cifração
    @Benchmark
    public byte[] testEncrypt() throws Exception {
        return encrypt(plainMessage.getBytes("UTF-8"), publicKey);
    }

    // Benchmark para decifração
    @Benchmark
    public byte[] testDecrypt() throws Exception {
        return decrypt(encryptedMessageDecrypt, privateKey);
    }

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

    public static PublicKey loadPublicKey(String filePath) throws Exception {
        String key = Files.readString(Paths.get(filePath))
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // Remove cabeçalhos e quebras de linha

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        String key = Files.readString(Paths.get(filePath))
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", ""); // Remove cabeçalhos e quebras de linha

        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    // Função de geração de chaves
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048); // Tamanho da chave (2048 bits)
        return keyPairGen.generateKeyPair();
    }

    // Função de cifração
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data); // Retorna a mensagem cifrada
    }

    // Função de decifração
    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data); // Retorna a mensagem decifrada
    }
}
