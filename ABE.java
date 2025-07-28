import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class ABE {
    // Generate public and private keys
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    // Encrypt the plain text
    public static String encrypt(String plainText, PublicKey publicKey, String[] attributes) throws Exception {
        // Generate a secret key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey secretKey = kg.generateKey();

        // Encrypt the secret key with ABE
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());

        // Encrypt the plain text with the secret key
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        // Return the encrypted secret key and the encrypted plain text
        return Base64.getEncoder().encodeToString(encryptedSecretKey) + ":" + Base64.getEncoder().encodeToString(encryptedBytes) + ":" + String.join(",", attributes);
    }

    // Decrypt the encrypted text
    public static String decrypt(String encryptedText, PrivateKey privateKey, String[] attributes) throws Exception {
        // Split the encrypted text into the encrypted secret key and the encrypted plain text
        String[] parts = encryptedText.split(":");
        byte[] encryptedSecretKey = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);
        String[] encryptedAttributes = parts[2].split(",");

        // Check if the attributes match
        boolean attributesMatch = true;
        for (String attribute : attributes) {
            boolean found = false;
            for (String encryptedAttribute : encryptedAttributes) {
                if (attribute.equals(encryptedAttribute)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                attributesMatch = false;
                break;
            }
        }

        if (!attributesMatch) {
            throw new Exception("Attributes do not match");
        }

        // Decrypt the secret key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] secretKeyBytes = cipher.doFinal(encryptedSecretKey);
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");

        // Decrypt the plain text
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        // Generate public and private keys
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the plain text
        String plainText = "Hello, World!";
        String[] attributes = {"admin", "user"};
        String encryptedText = encrypt(plainText, publicKey, attributes);
        System.out.println("Encrypted Text: " + encryptedText);

        // Decrypt the encrypted text
        String[] decryptionAttributes = {"admin", "user"};
        String decryptedText = decrypt(encryptedText, privateKey, decryptionAttributes);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}