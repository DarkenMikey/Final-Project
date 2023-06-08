
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

// The text to encrypt
String plaintext = "ZJC201918020429";

//ECC encryption and decryption
KeyPair eccKeyPair = EncryptionFunction.generateECCKeyPair(eccKeySize);
ECPublicKey eccPublicKey = (ECPublicKey) eccKeyPair.getPublic();
ECPrivateKey eccPrivateKey = (ECPrivateKey) eccKeyPair.getPrivate();

byte[] eccEncrypted = EncryptionFunction.encryptECC(plaintext, eccPublicKey);
String eccDecrypted = EncryptionFunction.decryptECC(eccEncrypted, eccPrivateKey);

System.out.println("ECC Encrypted: " + Base64.getEncoder().encodeToString(eccEncrypted));
System.out.println("ECC Decrypted: " + eccDecrypted);

//RSA encryption and decryption
KeyPair rsaKeyPair = EncryptionFunction.generateRSAKeyPair(rsaKeySize);
RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

byte[] rsaEncrypted = EncryptionFunction.encryptRSA(plaintext, rsaPublicKey);
String rsaDecrypted = EncryptionFunction.decryptRSA(rsaEncrypted, rsaPrivateKey);

System.out.println("RSA Encrypted: " + Base64.getEncoder().encodeToString(rsaEncrypted));
 System.out.println("RSA Decrypted: " + rsaDecrypted);

int rounds = 100; // Change this value to run different encryption and decryption rounds

 EncryptionFunction.timeTest(plaintext,rounds,eccKeySize,rsaKeySize);
}
}
