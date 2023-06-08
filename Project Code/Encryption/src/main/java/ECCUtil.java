// Classes for ECC algorithms
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class ECCUtil {
    // Add BouncyCastleProvider as the security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    // Method to generate ECC key pairs
    public static KeyPair generateECCKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        // Create KeyPairGenerator instance with EC algorithm and BC provider (Bouncy Castle)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(keySize);// Initialize KeyPairGenerator and set key length
        return keyPairGenerator.generateKeyPair();// Generate and return the key pair
    }
    // Cryptographic method using ECC public key
    public static byte[] encryptECC(String plaintext, ECPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");  // Create Cipher instance with ECIES and BC(Bouncy Castle) provider
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); // Initialize Cipher, set it to encryption mode, and encrypt with public key
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));// Encrypt the plaintext and return the encrypted ciphertext
    }
    // Decryption method using ECC private key
    public static String decryptECC(byte[] ciphertext, ECPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");// Decryption method using ECC private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);// Initialize Cipher, set it to decrypt mode, decrypt using private key
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);// Decrypt the ciphertext and return the decrypted plaintext
    }
}
