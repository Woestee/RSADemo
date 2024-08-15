// Alexander Woeste

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSADemo {
    private static final int KEY_SIZE_FAST = 32;    // Small key size for fast operatioons
    private static final int KEY_SIZE_MEDIUM = 64;  // Medium key size for balanced performance
    private static final int KEY_SIZE_SLOW = 128;   // Large key size for slower and more secure operations

    private BigInteger publicExponent;
    private BigInteger modulus;

    public RSADemo(int keySize) {   // Constructor that initilizes RSA with a given key size
        generateKeys(keySize);
    }

    private void generateKeys(int keySize) {    // Method to generate RSA keys
        Random rand = new Random();
        // Generate two random prime numbers
        BigInteger prime1 = BigInteger.probablePrime(keySize / 2, rand);
        BigInteger prime2 = BigInteger.probablePrime(keySize / 2, rand);
        // Calculate modulus n = p * q
        modulus = prime1.multiply(prime2);
        // Calculate Euler's totient function phi = (p-1) * (q-1)
        BigInteger totient = prime1.subtract(BigInteger.ONE).multiply(prime2.subtract(BigInteger.ONE));
        // Choose a public exponent e (commonly 65537)
        publicExponent = BigInteger.valueOf(65537);
        // Ensure e and phi are coprime (gcd(e, phi) = 1)
        while (totient.gcd(publicExponent).intValue() > 1) {
            publicExponent = publicExponent.add(BigInteger.valueOf(2));
        }
    }

    // Method to encrypt a message using the public key
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(publicExponent, modulus); // Encrypts using modular exponentiation
    }

    public static void main(String[] args) {    // Main method to run the RSA demonstration
        Scanner scanner = new Scanner(System.in);
        System.out.println("Choose the key size: ");
        System.out.println("1. Fast (32 bits)");
        System.out.println("2. Medium (64 bits)");
        System.out.println("3. Slow (128 bits)");
        int choice = scanner.nextInt();

        int keySize;
        switch (choice) {   // Allows user to select key size
            case 1:
                keySize = KEY_SIZE_FAST;
                break;
            case 2:
                keySize = KEY_SIZE_MEDIUM;
                break;
            case 3:
                keySize = KEY_SIZE_SLOW;
                break;
            default:
                System.out.println("Invalid choice. Using medium (64 bits) key size.");
                keySize = KEY_SIZE_MEDIUM;
        }

        RSADemo rsa = new RSADemo(keySize); // Initializes RSA with the chosen key size
        BigInteger message = new BigInteger("123456789");

        System.out.println("Original message: " + message);

        // Encrypts the messafe and measures the time taken
        long startTime = System.currentTimeMillis();
        BigInteger encryptedMessage = rsa.encrypt(message);
        long endTime = System.currentTimeMillis();
        double encryptionTime = (endTime - startTime) / 1000.0; // Convert to seconds
        System.out.println("Encrypted message: " + encryptedMessage);
        System.out.println("Encryption time: " + encryptionTime + " seconds");

        // Brute-force decryption (very slow and impractical for large key sizes)
        startTime = System.currentTimeMillis();
        boolean found = false;
        BigInteger decryptedMessage = BigInteger.ZERO;
        BigInteger one = BigInteger.ONE;
        // Trys every possible value to find the original message
        for (BigInteger i = BigInteger.ZERO; i.compareTo(rsa.modulus) < 0; i = i.add(one)) {
            if (rsa.encrypt(i).equals(encryptedMessage)) {
                found = true;
                decryptedMessage = i;
                break;
            }
        }
        endTime = System.currentTimeMillis();

        double decryptionTime = (endTime - startTime) / 1000.0; // Convert to seconds
        if (found) {
            System.out.println("Decrypted message: " + decryptedMessage);
        } else {
            System.out.println("Decryption not successful. Message not found.");
        }

        System.out.println("Brute-force decryption time: " + decryptionTime + " seconds");

        scanner.close();
    }
}