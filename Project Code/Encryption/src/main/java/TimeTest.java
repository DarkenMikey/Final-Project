
import java.util.Scanner;

//ECC and RSA100 round encryption and decryption time test
public class TimeTest{
    public static void main(String[] args) throws Exception {
        String message = "AC1314520DB";
        int rounds = 100; // Change this value to run different encryption and decryption rounds
        Scanner scanner = new Scanner(System.in);

        System.out.println("Please enter the ECC key length:");
        int eccKeySize = scanner.nextInt();

        System.out.println("Enter the RSA key length:");
        int rsaKeySize = scanner.nextInt();


        EncryptionFunction.timeTest(message, rounds,eccKeySize,rsaKeySize);
    }
}

