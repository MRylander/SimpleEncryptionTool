import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class SimpleEncryptionTool {

    /**
     * This is a simple tool for encrypting and decrypting messages using AES 128 bit encryption.
     *
     * Replace the sample `encryptionKey` with your encryption key.
     * Replace the sample `messageToEncrypt` with message you want to encrypt.
     * Replace the sample `messageToDecrypt` with message you want to decryption.
     */
    public static void main(String... args) {
        try {
            String encryptionKey = "SamplePassword"; // a.k.a. password
            String messageToEncrypt = "Sample message to encrypt!"; // sample message
            String messageToDecrypt = "D2+uaG+Whfi4Kn8q26hAS/oPz6MHZ4B8AA14eaXK+fE="; // sample encrypted message.

            encryptAndDisplay(encryptionKey, messageToEncrypt);
            decryptAndDisplay(encryptionKey, messageToDecrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5PADDING";

    private static IvParameterSpec getIv() throws UnsupportedEncodingException {
        return new IvParameterSpec("RandomInitVector".getBytes("UTF-8"));
    }

    private static String encryptAndDisplay(String key, String messageToEncrypt) throws Exception {
        SecretKeySpec hashedKey = hashKey(key);

        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, hashedKey, getIv());

        byte[] encrypted = cipher.doFinal(messageToEncrypt.getBytes());

        String encryptedMessage = DatatypeConverter.printBase64Binary(encrypted);

        System.out.println("**********************");
        System.out.println("* Encryption         *");
        System.out.println("**********************");
        System.out.println("Encrypting: " + messageToEncrypt);
        System.out.println("Encrypted Message:\n\n" + encryptedMessage);
        System.out.println();

        return encryptedMessage;
    }

    private static String decryptAndDisplay(String key, String messageToDecrypt) throws Exception {
        System.out.println("**********************");
        System.out.println("* Decryption         *");
        System.out.println("**********************");
        System.out.println("Decrypting: " + messageToDecrypt);
        System.out.println("Decrypted Message:\n");
        try {
            SecretKeySpec hashedKey = hashKey(key);

            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            cipher.init(Cipher.DECRYPT_MODE, hashedKey, getIv());

            byte[] decryptedMessageBytes = cipher.doFinal(DatatypeConverter.parseBase64Binary(messageToDecrypt));
            String decryptedMessage = new String(decryptedMessageBytes);


            System.out.println(decryptedMessage);

            return decryptedMessage;
        } catch (Exception e) {
            System.out.println("<ERROR: Could not decrypt message.>");
            return null;
        }
    }

    private static SecretKeySpec hashKey(String myKey) throws Exception {
        // convert to bytes
        byte[] key = myKey.getBytes("UTF-8");
        // apply oneway hash
        key = MessageDigest.getInstance("SHA-1").digest(key);
        // use only first 128 bit
        key = Arrays.copyOf(key, 16);
        return new SecretKeySpec(key, "AES");
    }
}