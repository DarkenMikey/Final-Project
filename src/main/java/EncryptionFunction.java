//EncryptionDemo contains RSA and ECC encryption algorithms
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The EncryptionFunction class contains methods for RSA and ECC encryption/decryption and timing testing.
 */
public class EncryptionFunction {
        static {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }

        public static KeyPair generateECCKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            String curveName;
            switch (keySize) {
                case 160:
                    curveName = "secp160r1"; // This elliptic curve is equivalent to 1024 bits of RSA security
                    break;
                case 192:
                    curveName = "secp192r1";// This elliptic curve is equivalent to 1536 bits of RSA security
                    break;
                case 256:
                    curveName = "secp256r1";// This elliptic curve is equivalent to 3072 bits of RSA security
                    break;
                case 384:
                    curveName = "secp384r1";// This elliptic curve is equivalent to 7680 bits of RSA security
                    break;
                case 521:
                    curveName = "secp521r1";// This elliptic curve is equivalent to 15360 bits of RSA security
                    break;

                // other key sizes
                default:
                    throw new InvalidAlgorithmParameterException("Unsupported key size: " + keySize);
            }
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
//KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
//keyPairGenerator.initialize(keySize);
//return keyPairGenerator.generateKeyPair();


        public static byte[] encryptECC(String plaintext, ECPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        }

        public static String decryptECC(byte[] ciphertext, ECPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        }

        public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        }

        public static byte[] encryptRSA(String plaintext, RSAPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        }

        public static String decryptRSA(byte[] ciphertext, RSAPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        }


    // encryption time function
        public static void timeTest(String message, int rounds,int eccKeySize,int rsaKeySize) throws Exception {
            //生成ECC和RSA密钥对
            KeyPair eccKeyPair = generateECCKeyPair(eccKeySize);
            ECPublicKey eccPublicKey = (ECPublicKey) eccKeyPair.getPublic();
            ECPrivateKey eccPrivateKey = (ECPrivateKey) eccKeyPair.getPrivate();

            KeyPair rsaKeyPair = generateRSAKeyPair(rsaKeySize);
            RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

            long encryptionStartTime, encryptionEndTime, decryptionStartTime, decryptionEndTime;

    //ECC encryption and decryption
            encryptionStartTime = System.currentTimeMillis();
            for (int i = 0; i < 100; i++) {
                byte[] encryptedECC = encryptECC(message, eccPublicKey);
            }
            encryptionEndTime = System.currentTimeMillis();

            decryptionStartTime = System.currentTimeMillis();
            for (int i = 0; i < 100; i++) {
                byte[] encryptedECC = encryptECC(message, eccPublicKey);
                String decryptedECC = decryptECC(encryptedECC, eccPrivateKey);
            }
            decryptionEndTime = System.currentTimeMillis();

            System.out.println("ECC encryption time for " + 100 + " rounds: " + (encryptionEndTime - encryptionStartTime) + " ms");
            System.out.println("ECC decryption time for " + 100 + " rounds: " + (decryptionEndTime - decryptionStartTime) + " ms");

            //RSA encryption and decryption
            encryptionStartTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                byte[] encryptedRSA = encryptRSA(message, rsaPublicKey);
            }
            encryptionEndTime = System.currentTimeMillis();

            decryptionStartTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                byte[] encryptedRSA = encryptRSA(message, rsaPublicKey);
                String decryptedRSA = decryptRSA(encryptedRSA, rsaPrivateKey);
            }
            decryptionEndTime = System.currentTimeMillis();

            System.out.println("RSA encryption time for " + 100 + " rounds: " + (encryptionEndTime - encryptionStartTime) + " ms");
            System.out.println("RSA decryption time for " + 100 + " rounds: " + (decryptionEndTime - decryptionStartTime) + " ms");
        }

    }
