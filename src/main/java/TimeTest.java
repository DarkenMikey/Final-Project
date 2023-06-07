
import java.util.Scanner;

//ECC与RSA100轮加密解密时间测试
public class TimeTest{
    public static void main(String[] args) throws Exception {
        String message = "AC1314520DB";
        int rounds = 1; // 更改此值以运行不同的加密和解密轮数
        Scanner scanner = new Scanner(System.in);

        System.out.println("请输入 ECC 密钥长度 (推荐 256):");
        int eccKeySize = scanner.nextInt();

        System.out.println("请输入 RSA 密钥长度 (推荐 2048):");
        int rsaKeySize = scanner.nextInt();


        EncryptionFunction.timeTest(message, rounds,eccKeySize,rsaKeySize);
    }
}

