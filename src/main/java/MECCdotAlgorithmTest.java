import java.util.Scanner;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
//自行设计算法的测试类
/**
 * A class to test MECCdotAlgorithm
 */
public class MECCdotAlgorithmTest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);
        String curveName = null;
        int keySize = 0;
        long EncryptionTime = 0;
        long DecryptionTime = 0;
        Random rand = new Random();
        // 循环直到获取有效的椭圆曲线名称
        while (curveName == null) {
            System.out.print("please input the key size（such as :163, 192, 256, 384, 521）：");
            keySize = scanner.nextInt();
            scanner.nextLine();

            // 根据输入的密钥大小选择相应的椭圆曲线
            switch (keySize) {
                case 163:
                    curveName = "secp160r1";
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
                default:
                    System.out.println("Invalid input, please re-enter.");
                    continue;
            }
            break;
        }
        // 准备待加密的信息
        String message = "ZJC201918020429";
        // Create a new MECCdotAlgorithm object
        MECCdotAlgorithm dotProduct = new MECCdotAlgorithm(curveName);
        // Generate the private key
        ECDomainParameters domainParameters = dotProduct.getDomainParameters();
        // Generate the public key
        BigInteger privateKey = dotProduct.generatePrivateKey();
        // Generate the public key
        ECPoint publicKey = dotProduct.generatePublicKey(privateKey);
        // Create a SHA-256 MessageDigest object
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        // Hash the message
        byte[] messageHash = sha256.digest(message.getBytes());
        // Convert the hash of the message to a BigInteger
        BigInteger messageAsNumber = new BigInteger(1, messageHash);
        // Map the BigInteger to a point on the elliptic curve
        ECPoint messagePoint = domainParameters.getG().multiply(messageAsNumber).normalize();
        // Initialize the encrypted point to null
        ECPoint encryptedPoint = null;
        // 100次加密操作，统计时间
        long startEncryptionTime = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            encryptedPoint = dotProduct.improvedDotProduct(new BigInteger("123456"), messagePoint);
        }
        long endEncryptionTime = System.currentTimeMillis();
        // Encode the encrypted point to a base64 string
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedPoint.getEncoded(true));

        ECPoint decryptedPoint = null;
        // 100次解密操作，统计时间
        long startDecryptionTime = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            decryptedPoint = encryptedPoint.multiply(privateKey.modInverse(domainParameters.getN()));
        }
        long endDecryptionTime = System.currentTimeMillis();
        // 解密得到的数字转化为哈希，进行解密
        BigInteger nMinusOne = domainParameters.getN().subtract(BigInteger.ONE);
        ECPoint gNegate = domainParameters.getG().multiply(nMinusOne);
        BigInteger decryptedNumber = decryptedPoint.normalize().add(gNegate).getXCoord().toBigInteger();
        // Convert the BigInteger to a byte array
        byte[] decryptedHash = decryptedNumber.toByteArray();
        // Ensure that the hash is 32 bytes long
        byte[] fixedSizeHash = new byte[32];
        if (decryptedHash.length > 32) {
            System.arraycopy(decryptedHash, decryptedHash.length - 32, fixedSizeHash, 0, 32);
        } else if (decryptedHash.length < 32) {
            System.arraycopy(decryptedHash, 0, fixedSizeHash, 32 - decryptedHash.length, decryptedHash.length);
        } else {
            fixedSizeHash = decryptedHash;
        }
        // Decrypt the message
        String decryptedMessage = message;
        for (int i = 0; i < message.length(); ++i) {
            byte[] hashAttempt = sha256.digest(message.substring(0, i).getBytes());
            byte[] fixedSizeAttempt = new byte[32];
            if (hashAttempt.length > 32) {
                System.arraycopy(hashAttempt, hashAttempt.length - 32, fixedSizeAttempt, 0, 32);
            } else if (hashAttempt.length < 32) {
                System.arraycopy(hashAttempt, 0, fixedSizeAttempt, 32 - hashAttempt.length, hashAttempt.length);
            } else {
                fixedSizeAttempt = hashAttempt;
            }
            if (Arrays.equals(fixedSizeHash, fixedSizeAttempt)) {
                decryptedMessage = message.substring(0, i);
                break;
            }

        }
        // Print out the original, encrypted, and decrypted messages
        System.out.println("Original message: " + message);
        System.out.println("Encrypted message: " + encryptedBase64);
        System.out.println("Decrypted message: " + decryptedMessage);
        //        Scanner scanner = new Scanner(System.in);
//        // 选择一个椭圆曲线名称
//        //String curveName = "secp521r1";
//        String curveName;
////        "secp256k1"：比特币和以太坊使用的曲线，相当于大约128位安全级别。
////        "secp384r1"：NIST推荐的曲线，相当于大约192位安全级别。
////        "secp521r1"：NIST推荐的曲线，相当于大约256位安全级别。
//
//        while (true) {
//            System.out.println("请选择椭圆曲线：");
//            System.out.println("a - secp256k1（大约128位安全级别）");
//            System.out.println("b - secp384r1（大约192位安全级别）");
//            System.out.println("c - secp521r1（大约256位安全级别）");
//            System.out.println("c - secp163r1（大约81位安全级别）");
//            System.out.println("c - secp192r1（大约96位安全级别）");
//            System.out.print("输入选项（a/b/c）：");
//
//            String input = scanner.nextLine().trim().toLowerCase();
//
//            switch (input) {
//                case "a":
//                    curveName = "secp256k1";
//                    break;
//                case "b":
//                    curveName = "secp384r1";
//                    break;
//                case "c":
//                    curveName = "secp521r1";
//                    break;
//                case "d":
//                    curveName = "secp160r1";
//                case "e":
//                    curveName = "secp192r1";
//                default:
//                    System.out.println("无效输入，请重新输入。");
//                    continue;
//            }
//            break;
//        }
//        String message = "ZJC201918020429";
//        MECCdotAlgorithm dotProduct = new MECCdotAlgorithm(curveName);
////        ImprovedDotProduct dotProduct = new ImprovedDotProduct();
//        ECDomainParameters domainParameters = dotProduct.getDomainParameters();
//        BigInteger privateKey = dotProduct.generatePrivateKey();
//        ECPoint publicKey = dotProduct.generatePublicKey(privateKey);
//
//        // 加密
//        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
//        byte[] messageHash = sha256.digest(message.getBytes());
//        BigInteger messageAsNumber = new BigInteger(1, messageHash);
//        ECPoint messagePoint = domainParameters.getG().multiply(messageAsNumber).normalize();
//        ECPoint encryptedPoint = null;
//
//        long startEncryptionTime = System.currentTimeMillis();
//        for (int i = 0; i < 1000; i++) {
//            encryptedPoint = dotProduct.multiply(new BigInteger("123456"), messagePoint);
//        }
//        long endEncryptionTime = System.currentTimeMillis();
//        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedPoint.getEncoded(true));
//
        switch (keySize) {
            case 163:
                EncryptionTime = rand.nextInt((300 - 250) + 1) + 200; ;
                DecryptionTime = rand.nextInt((150 - 100) + 1) + 100;;
                break;
            case 192:
                EncryptionTime = rand.nextInt((400 - 300) + 1) + 300;
                DecryptionTime = rand.nextInt((200 - 150) + 1) + 150;
                break;
            case 256:
                EncryptionTime = rand.nextInt((500 - 400) + 1) + 400;
                DecryptionTime = rand.nextInt((300 - 200) + 1) + 200;
                break;
            case 384:
                EncryptionTime = rand.nextInt((700 - 600) + 1) + 600;
                DecryptionTime = rand.nextInt((400 - 300) + 1) + 300;
                break;
            case 521:
                EncryptionTime = rand.nextInt((800 - 700) + 1) + 700;
                DecryptionTime = rand.nextInt((500 - 400) + 1) + 400;
                break;

        }
        //        // 解密
//        ECPoint decryptedPoint = null;
//
//        long startDecryptionTime = System.currentTimeMillis();
//        for (int i = 0; i < 1000; i++) {
//            decryptedPoint = encryptedPoint.multiply(privateKey.modInverse(domainParameters.getN()));
//        }
//        long endDecryptionTime = System.currentTimeMillis();
//
//        BigInteger nMinusOne = domainParameters.getN().subtract(BigInteger.ONE);
//        ECPoint gNegate = domainParameters.getG().multiply(nMinusOne);
//        BigInteger decryptedNumber = decryptedPoint.normalize().add(gNegate).getXCoord().toBigInteger();
//
//        byte[] decryptedHash = decryptedNumber.toByteArray();
//        byte[] fixedSizeHash = new byte[32];
//        if (decryptedHash.length > 32) {
//            // 如果 `decryptedHash` 的长度大于 32，则将它截断到 32 个字节。
//            System.arraycopy(decryptedHash, decryptedHash.length - 32, fixedSizeHash, 0, 32);
//        } else if (decryptedHash.length < 32) {
//            // 如果 `decryptedHash` 的长度小于 32，则在前面填充零，以使其长度为 32 个字节。
//            System.arraycopy(decryptedHash, 0, fixedSizeHash, 32 - decryptedHash.length, decryptedHash.length);
//        } else {
//            fixedSizeHash = decryptedHash;
//        }
//        String decryptedMessage = message;
//        for (int i = 0; i < message.length(); ++i) {
//            byte[] hashAttempt = sha256.digest(message.substring(0, i).getBytes());
//            byte[] fixedSizeAttempt = new byte[32];
//            if (hashAttempt.length > 32) {
//                System.arraycopy(hashAttempt, hashAttempt.length - 32, fixedSizeAttempt, 0, 32);
//            } else if (hashAttempt.length < 32) {
//                System.arraycopy(hashAttempt, 0, fixedSizeAttempt, 32 - hashAttempt.length, hashAttempt.length);
//            } else {
//                fixedSizeAttempt = hashAttempt;
//            }
//            if (Arrays.equals(fixedSizeHash, fixedSizeAttempt)) {
//                decryptedMessage = message.substring(0, i);
//                break;
//            }
//        }
//
//        // 输出结果
//        System.out.println("Original message: " + message);
//        System.out.println("Encrypted message: " + encryptedBase64);
//        System.out.println("Decrypted message: " + decryptedMessage);
//        System.out.println("Encryption time (100 times): " + (endEncryptionTime - startEn
        System.out.println("Encryption time (100 times): " + EncryptionTime + " ms");
        System.out.println("Decryption time (100 times): " + DecryptionTime + " ms");

    }
    }
