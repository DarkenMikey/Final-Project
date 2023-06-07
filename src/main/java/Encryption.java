
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Scanner;


public class Encryption {
public static void main(String[] args) throws Exception {
Scanner scanner = new Scanner(System.in);

    System.out.println("Please input the key size of ECC :");
int eccKeySize = scanner.nextInt();

    System.out.println("Please input the key size of RSA :");
int rsaKeySize = scanner.nextInt();

//要加密的文本
String plaintext = "ZJC201918020429";

//ECC加密和解密
KeyPair eccKeyPair = EncryptionFunction.generateECCKeyPair(eccKeySize);
ECPublicKey eccPublicKey = (ECPublicKey) eccKeyPair.getPublic();
ECPrivateKey eccPrivateKey = (ECPrivateKey) eccKeyPair.getPrivate();

byte[] eccEncrypted = EncryptionFunction.encryptECC(plaintext, eccPublicKey);
String eccDecrypted = EncryptionFunction.decryptECC(eccEncrypted, eccPrivateKey);

System.out.println("ECC Encrypted: " + Base64.getEncoder().encodeToString(eccEncrypted));
System.out.println("ECC Decrypted: " + eccDecrypted);

//RSA加密和解密
KeyPair rsaKeyPair = EncryptionFunction.generateRSAKeyPair(rsaKeySize);
RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

byte[] rsaEncrypted = EncryptionFunction.encryptRSA(plaintext, rsaPublicKey);
String rsaDecrypted = EncryptionFunction.decryptRSA(rsaEncrypted, rsaPrivateKey);

System.out.println("RSA Encrypted: " + Base64.getEncoder().encodeToString(rsaEncrypted));
 System.out.println("RSA Decrypted: " + rsaDecrypted);

int rounds = 100; // 更改此值以运行不同的加密和解密轮数

 EncryptionFunction.timeTest(plaintext,rounds,eccKeySize,rsaKeySize);
}
}
