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
// Design our own test class for the algorithm
/**
 * A class to test MECCdotAlgorithm
 */
public class MECCdotAlgorithmTest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
                Scanner scanner = new Scanner(System.in);
                String curveName = null;
                int keySize;

                while (curveName == null) {
                    System.out.print("please input the key size（such as :160, 192, 256, 384, 521）：");
                    keySize = scanner.nextInt();
                    scanner.nextLine();


                    switch (keySize) {
                        case 160:
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

                String message = "ZJC201918020429";
                MECCdotAlgorithm dotProduct = new MECCdotAlgorithm(curveName);
                ECDomainParameters domainParameters = dotProduct.getDomainParameters();
                BigInteger privateKey = dotProduct.generatePrivateKey();
                ECPoint publicKey = dotProduct.generatePublicKey(privateKey);

                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] messageHash = sha256.digest(message.getBytes());
                BigInteger messageAsNumber = new BigInteger(1, messageHash);
                ECPoint messagePoint = domainParameters.getG().multiply(messageAsNumber).normalize();
                ECPoint encryptedPoint = null;

                long startEncryptionTime = System.currentTimeMillis();
                for (int i = 0; i < 100; i++) {
                    encryptedPoint = dotProduct.improvedDotProduct(new BigInteger("123456"), messagePoint);
                }
                long endEncryptionTime = System.currentTimeMillis();
                String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedPoint.getEncoded(true));

                ECPoint decryptedPoint = null;

                long startDecryptionTime = System.currentTimeMillis();
                for (int i = 0; i < 100; i++) {
                    decryptedPoint = encryptedPoint.multiply(privateKey.modInverse(domainParameters.getN()));
                }
                long endDecryptionTime = System.currentTimeMillis();

                BigInteger nMinusOne = domainParameters.getN().subtract(BigInteger.ONE);
                ECPoint gNegate = domainParameters.getG().multiply(nMinusOne);
                BigInteger decryptedNumber = decryptedPoint.normalize().add(gNegate).getXCoord().toBigInteger();

                byte[] decryptedHash = decryptedNumber.toByteArray();
                byte[] fixedSizeHash = new byte[32];
                if (decryptedHash.length > 32) {
                    System.arraycopy(decryptedHash, decryptedHash.length - 32, fixedSizeHash, 0, 32);
                } else if (decryptedHash.length < 32) {
                    System.arraycopy(decryptedHash, 0, fixedSizeHash, 32 - decryptedHash.length, decryptedHash.length);
                } else {
                    fixedSizeHash = decryptedHash;
                }
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

                System.out.println("Original message: " + message);
                System.out.println("Encrypted message: " + encryptedBase64);
                System.out.println("Decrypted message: " + decryptedMessage);
                System.out.println("Encryption time (100 times): " + (endEncryptionTime - startEncryptionTime) + " ms");
                System.out.println("Decryption time (100 times): " + (endDecryptionTime - startDecryptionTime) + " ms");
            }
        }