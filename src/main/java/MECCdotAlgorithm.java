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
 * 椭圆曲线密码学改进的点乘算法类。
 */
public class MECCdotAlgorithm {
    private ECDomainParameters domainParameters;// 定义域参数

    /**
     * 构造函数，根据曲线名称设置椭圆曲线参数。
     * @param curveName 椭圆曲线名称。
     */
    public MECCdotAlgorithm(String curveName) {
        X9ECParameters params;
        if (curveName.equals("secp160r1") || curveName.equals("secp192r1")) {
            params = SECNamedCurves.getByName(curveName);// 根据名称获取曲线参数
        } else {
            params = CustomNamedCurves.getByName(curveName);// 根据名称获取自定义曲线参数
        }
        domainParameters = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }
    /**
     * 生成私钥的方法。
     * @return 256位随机私钥。
     */
    public BigInteger generatePrivateKey() {
        return new BigInteger(256, new SecureRandom());
    }// 生成并返回随机私钥

    /**
     * 根据私钥生成公钥的方法。
     * @param privateKey 私钥。
     * @return 公钥。
     */
    public ECPoint generatePublicKey(BigInteger privateKey) {
        return domainParameters.getG().multiply(privateKey); // 生成并返回公钥
    }// 生成并返回公钥
    /**
     * 改进的点乘算法的方法，用于计算一个点在曲线上的k倍。
     * @param k 倍数。
     * @param P 曲线上的点。
     * @return Q=kP的结果。
     */
    public ECPoint improvedDotProduct(BigInteger k, ECPoint P) {
        ArrayList<Integer> arr = new ArrayList<>();// 创建一个ArrayList用于存储k的分解结果
        BigInteger bigTwo = BigInteger.valueOf(2);
        BigInteger bigThree = BigInteger.valueOf(3);
        BigInteger bigFour = BigInteger.valueOf(4);
        BigInteger copyK = new BigInteger(k.toString());// 创建k的副本以避免修改原始值
        int i = 0;
        // 将k分解为基本操作序列
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
        // 计算Q=kP的结果
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

        return Q;// 计算Q=kP的结果
    }
    /**
     * 获取椭圆曲线域参数的方法。
     * @return 域参数。
     */
    public ECDomainParameters getDomainParameters() {
        return domainParameters;
    }// 返回域参数
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
