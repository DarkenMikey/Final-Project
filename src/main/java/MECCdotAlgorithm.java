//自行设计的算法
/**代码以及算法思路：
 * 在点乘计算中，给定一个椭圆曲线上的点P和一个整数k，计算kP的结果。
 * 这个过程可以通过重复执行加法操作来实现，但是传统的点乘算法可能会导致计算量过大，特别是当k非常大时。
 * 改进的点乘算法通过将k分解成一个简单的基本操作序列来减少计算量。
 * 这个代码实现了以下功能：
 * 使用secp256k1曲线作为椭圆曲线参数。
 * 生成一个随机私钥和相应的公钥。
 * 实现了一个改进的点乘算法，用于计算一个点在曲线上的k倍。
 * 提供了访问椭圆曲线参数的方法getDomainParameters()。
 *
 *
 * 伪代码：
 * Improved Dot Product Algorithm:
 *
 * Input: positive integer k
 * Output: Q=kP
 * Variables used: I, arr[]
 * Step 1: denote k by array[i]
 * While loop starts: i=0
 * While k≠1
 * While k mod 4 = 0
 * K = k/4, arr[i++] = 4.
 * While k mod 3 = 0
 * K=k/3, arr[i++] = 3.
 * If k mod 3 = 1 k=(k-1)/3, arr[i++] = 0.
 * Else if k mod 2 = 1 k=(k-1)/2, arr[i++] = 1.
 * Else k=k/2, arr[i++] = 2.
 * End of loop
 * Step 2, calculate Q
 * For the start of the loop, let I = i-1 and kP = P
 * For i=I; i>0; i=i-1
 * S = arr[i++]
 * case 0: then kP = 3kP + P.
 * case 1: then kP = 2kP + P.
 * case 2: then kP = 2kP.
 * case 3: then kP = 3kP.
 * case 4: then kP = 4kP.
 * Q = kP
 * End
 */
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

/**
 * Elliptic curve cryptography improved point multiplication algorithm class.
 */
public class MECCdotAlgorithm {
    private ECDomainParameters domainParameters;// Domain parameters

    /**
     * Constructor that sets the elliptic curve parameters based on the curve name.
     * @param curveName The name of an elliptic curve.
     */
    public MECCdotAlgorithm(String curveName) {
        X9ECParameters params;
        if (curveName.equals("secp160r1") || curveName.equals("secp192r1")) {
            params = SECNamedCurves.getByName(curveName);// Get curve parameters by name
        } else {
            params = CustomNamedCurves.getByName(curveName);// Get custom curve parameters by name
        }
        domainParameters = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }
    /**
     * The method to generate the private key.
     * @return 256-bit random private key.
     */
    public BigInteger generatePrivateKey() {
        return new BigInteger(256, new SecureRandom());
    }// Generate and return a random private key

    /**
     * A method of generating a public key from a private key.
     * @param privateKey Private key.
     * @return public key.
     */
    public ECPoint generatePublicKey(BigInteger privateKey) {
        return domainParameters.getG().multiply(privateKey); // Generate and return the public key
    }// Generate and return the public key

    /**
     * The method of the modified point multiplication algorithm is used to calculate k times of a point on the curve.
     * @param k multiples.
     * @param P points on the curve.
     * @return Q= result of kP.
     */
    public ECPoint improvedDotProduct(BigInteger k, ECPoint P) {
        ArrayList<Integer> arr = new ArrayList<>();// Create an ArrayList to store the factorization of k
        BigInteger bigTwo = BigInteger.valueOf(2);
        BigInteger bigThree = BigInteger.valueOf(3);
        BigInteger bigFour = BigInteger.valueOf(4);
        BigInteger copyK = new BigInteger(k.toString());// Create a copy of k to avoid modifying the original value
        int i = 0;
        // Decompose k into a sequence of basic operations
        while (!copyK.equals(BigInteger.ONE)) {
            if (copyK.mod(bigFour).equals(BigInteger.ZERO)) {
                copyK = copyK.divide(bigFour);
                arr.add(4);
            } else if (copyK.mod(bigThree).equals(BigInteger.ZERO)) {
                copyK = copyK.divide(bigThree);
                arr.add(3);
            } else if (copyK.mod(bigThree).equals(BigInteger.ONE)) {
                copyK = copyK.subtract(BigInteger.ONE).divide(bigThree);
                arr.add(0);
            } else if (copyK.mod(bigTwo).equals(BigInteger.ONE)) {
                copyK = copyK.subtract(BigInteger.ONE).divide(bigTwo);
                arr.add(1);
            } else {
                copyK = copyK.divide(bigTwo);
                arr.add(2);
            }
            i++;
        }
        // compute the result of Q=kP
        ECPoint Q = P;
        for (int j = i - 1; j >= 0; j--) {
            switch (arr.get(j)) {
                case 0:
                    Q = Q.multiply(bigThree).add(P);
                    break;
                case 1:
                    Q = Q.multiply(bigTwo).add(P);
                    break;
                case 2:
                    Q = Q.multiply(bigTwo);
                    break;
                case 3:
                    Q = Q.multiply(bigThree);
                    break;
                case 4:
                    Q = Q.multiply(bigFour);
                    break;
            }
        }

        return Q;// compute the result of Q=kP
    }
    /**
     * The method of obtaining the elliptic curve domain parameters.
     * @return domain parameter.
     */
    public ECDomainParameters getDomainParameters() {
        return domainParameters;
    }// Return domain arguments
}
//import org.bouncycastle.crypto.ec.CustomNamedCurves;
//import org.bouncycastle.crypto.params.ECDomainParameters;
//import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.math.ec.FixedPointCombMultiplier;
//
///
//
//
//import java.math.BigInteger;
//import java.security.SecureRandom;
//import java.util.ArrayList;
//public class MECCdotAlgorithm {
//    private ECDomainParameters domainParameters;
//
//    public MECCdotAlgorithm(String curveName) {
//        domainParameters = new ECDomainParameters(
//                CustomNamedCurves.getByName(curveName).getCurve(),
//                CustomNamedCurves.getByName(curveName).getG(),
//                CustomNamedCurves.getByName(curveName).getN(),
//                CustomNamedCurves.getByName(curveName).getH());
//    }
//
//    public ECPoint generatePublicKey(BigInteger privateKey) {
//        return new FixedPointCombMultiplier().multiply(domainParameters.getG(), privateKey);
//    }
//
//    public BigInteger generatePrivateKey() {
//        return new BigInteger(256, new SecureRandom());
//    }
//
//    public ECPoint multiply(BigInteger k, ECPoint P) {
//        if (!P.isValid()) {
//            throw new IllegalArgumentException("Invalid point");
//        }
//        if (!P.getCurve().equals(domainParameters.getCurve())) {
//            throw new IllegalArgumentException("Point not on curve");
//        }
//        return new FixedPointCombMultiplier().multiply(P, k);
//    }
//
//    public ECDomainParameters getDomainParameters() {
//        return domainParameters;
//    }
//}
