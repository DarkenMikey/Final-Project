//ECC算法的类
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
    // 添加BouncyCastleProvider作为安全提供者
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    // 生成ECC密钥对的方法
    public static KeyPair generateECCKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        // 创建KeyPairGenerator实例，指定算法为EC，提供者为BC(Bouncy Castle)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(keySize);// 初始化KeyPairGenerator，设置密钥长度
        return keyPairGenerator.generateKeyPair();// 生成并返回密钥对
    }
    // 使用ECC公钥进行加密的方法
    public static byte[] encryptECC(String plaintext, ECPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");  // 创建Cipher实例，指定算法为ECIES，提供者为BC(Bouncy Castle)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); // 初始化Cipher，设置为加密模式，使用公钥进行加密
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));// 对明文进行加密，并返回加密后的密文
    }
    // 使用ECC私钥进行解密的方法
    public static String decryptECC(byte[] ciphertext, ECPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("ECIES", "BC"); // 使用ECC私钥进行解密的方法
        cipher.init(Cipher.DECRYPT_MODE, privateKey);// 初始化Cipher，设置为解密模式，使用私钥进行解密
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);// 对密文进行解密，并返回解密后的明文
    }
}
