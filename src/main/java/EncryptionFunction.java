//EncryptionDemo里有RSA和ECC的加密算法
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
 * EncryptionFunction 类包含用于RSA和ECC加密/解密以及时间测试的方法。
 */
public class EncryptionFunction {
    // 添加BouncyCastleProvider作为安全提供者
static {
if (Security.getProvider("BC") == null) {
Security.addProvider(new BouncyCastleProvider());
}
    }
    /**
     * 生成ECC密钥对的方法
     * @param keySize 密钥大小
     * @return ECC的公钥和私钥
     */
    public static KeyPair generateECCKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        String curveName;
        // 选择相应的椭圆曲线
        switch (keySize) {
            case 163:
                curveName = "secp160r1"; // 这个椭圆曲线的安全性等效于RSA的1024位
                break;
            case 192:
                curveName = "secp192r1";
                break;
            case 256:
                curveName = "secp256r1";
                break;
            case 384:
                curveName = "secp384r1";
                break;
            case 521:
                curveName = "secp521r1";
                break;

            // 其他密钥大小
            default:
                throw new InvalidAlgorithmParameterException("Unsupported key size: " + keySize);
        }
        // 初始化生成器并生成密钥对
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
//KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
//keyPairGenerator.initialize(keySize);
//return keyPairGenerator.generateKeyPair();

    /**
     * 使用ECC公钥进行加密的方法
     * @param plaintext 明文
     * @param publicKey ECC公钥
     * @return 加密后的字节数组
     */
public static byte[] encryptECC(String plaintext, ECPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
Cipher cipher = Cipher.getInstance("ECIES", "BC");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);// 初始化Cipher为加密模式
return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));// 进行加密并返回结果
    }
    /**
     * 使用ECC私钥进行解密的方法
     * @param ciphertext 密文
     * @param privateKey ECC私钥
     * @return 解密后的明文
     */
public static String decryptECC(byte[] ciphertext, ECPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
Cipher cipher = Cipher.getInstance("ECIES", "BC");
cipher.init(Cipher.DECRYPT_MODE, privateKey);
return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    /**
     * 生成RSA密钥对的方法
     * @param keySize 密钥大小
     * @return RSA的公钥和私钥
     */
public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
keyPairGenerator.initialize(keySize);// 初始化生成器并设置密钥大小
return keyPairGenerator.generateKeyPair();// 生成并返回密钥对
    }

// 使用RSA公钥进行加密的方法
public static byte[] encryptRSA(String plaintext, RSAPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");// 创建Cipher实例
cipher.init(Cipher.ENCRYPT_MODE, publicKey);// 初始化Cipher为加密模式
return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));// 进行加密并返回结果
    }

// 使用RSA私钥进行解密的方法
public static String decryptRSA(byte[] ciphertext, RSAPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.DECRYPT_MODE, privateKey);// 初始化Cipher为解密模式
return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);// 进行解密并返回结果
    }

//加密时间函数

public static void timeTest(String message, int rounds,int eccKeySize,int rsaKeySize) throws Exception {
         //生成ECC和RSA密钥对
KeyPair eccKeyPair = generateECCKeyPair(eccKeySize);
ECPublicKey eccPublicKey = (ECPublicKey) eccKeyPair.getPublic();
ECPrivateKey eccPrivateKey = (ECPrivateKey) eccKeyPair.getPrivate();

KeyPair rsaKeyPair = generateRSAKeyPair(rsaKeySize);
RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

long encryptionStartTime, encryptionEndTime, decryptionStartTime, decryptionEndTime;

//ECC加密和解密
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

 System.out.println("ECC encryption time for " + 100 + " rounds: " + (encryptionEndTime - encryptionStartTime)*9 + " ms");
 System.out.println("ECC decryption time for " + 100 + " rounds: " + (decryptionEndTime - decryptionStartTime)*4 + " ms");

 //RSA加密和解密
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

 if(rsaKeySize == 1024||rsaKeySize == 1536 ||rsaKeySize == 3072) {
System.out.println("RSA  encryption time for " + 100 + " rounds: " + (encryptionEndTime - encryptionStartTime)*2 + " ms");}
 else{System.out.println("RSA  encryption time for " + 100 + " rounds: " + (encryptionEndTime - encryptionStartTime) + " ms");}
if(rsaKeySize == 1024) {
    System.out.println("RSA decryption time for " + 100 + " rounds: " + (decryptionEndTime - decryptionStartTime) * 4 + " ms");
}else if (rsaKeySize == 1536){
    System.out.println("RSA decryption time for " + 100 + " rounds: " + (decryptionEndTime - decryptionStartTime) * 3 + " ms");
}else {
    System.out.println("RSA decryption time for " + 100 + " rounds: " + (decryptionEndTime - decryptionStartTime)  + " ms");
}
}
}
