import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class PBKDF2 {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter password: ");
        String passwordStr = scanner.nextLine();
        byte[] password = passwordStr.getBytes();

        System.out.print("Enter salt: ");
        String saltStr = scanner.nextLine();
        byte[] salt = saltStr.getBytes();

        int iterationCount = 1000;

        System.out.print("Enter key length (in bits): ");
        int kLen = scanner.nextInt();

        byte[] masterKey = deriveMasterKey(password, salt, iterationCount, kLen);
        System.out.println("Derived master key: " + bytesToHex(masterKey));
    }

    public static byte[] deriveMasterKey(byte[] password, byte[] salt, int iterationCount, int kLen) throws NoSuchAlgorithmException {
        String prf = "SHA-256";
        int hLen = getHashLength(prf);

        if (kLen > ((2L << 32 - 1) * hLen)) {
            throw new IllegalArgumentException("kLen exceeds maximum value allowed");
        }

        int length = kLen / hLen;
        int r = kLen - (length - 1) * hLen;

        byte[] T = new byte[0];
        for (int i = 1; i <= length; i++) {
            byte[] T_i = new byte[hLen];
            byte[] U = concatenateByteArrays(salt, intToBytes(i));
            for (int j = 0; j < iterationCount; j++) {
                U = hmac(password, U, prf);
                T_i = xorByteArrays(T_i, U);
            }
            T = concatenateByteArrays(T, T_i);
        }

        byte[] masterKey = new byte[kLen / 8];
        System.arraycopy(T, 0, masterKey, 0, kLen / 8);
        return masterKey;
    }

    private static int getHashLength(String prf) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(prf).getDigestLength();
    }

    private static byte[] hmac(byte[] key, byte[] data, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }

    private static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] intToBytes(int value) {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            result[3 - i] = (byte) (value >> (i * 8));
        }
        return result;
    }

    private static byte[] xorByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}