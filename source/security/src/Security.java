package security.src;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Arrays;

public class Security {

    private static final String ALGORITHM_GCM = "AES/GCM/NoPadding";
    private static final String ALGORITHM = "AES";
    private static final int TAG_LENGTH_BIT = 128;
    private static final String RSA_ALGORITHM = "RSA";

    public static byte[] encrypt(byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_GCM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_GCM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, new byte[12]);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return cipher.doFinal(data);
    }

    public static String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public static SecretKey generateSecretKey() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(2048);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static void savePublicKey(PublicKey publicKey, String keyFile) throws FileNotFoundException, IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(keyFile))) {
            out.writeObject(publicKey);
        }
    }

    public static PublicKey loadPublicKey(String keyFile) throws FileNotFoundException, IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(keyFile))) {
            return (PublicKey) in.readObject();
        }
    }

    public static void savePrivateKey(PrivateKey privateKey, String keyFile) throws FileNotFoundException, IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(keyFile))) {
            out.writeObject(privateKey);
        }
    }

    public static PrivateKey loadPrivateKey(String keyFile) throws FileNotFoundException, IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(keyFile))) {
            return (PrivateKey) in.readObject();
        }
    }

    public static void saveSecretKey(SecretKey secretKey, String keyFile) throws FileNotFoundException, IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(keyFile))) {
            out.writeObject(secretKey);
        }
    }

    public static SecretKey loadSecretKey(String keyFile) throws FileNotFoundException, IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(keyFile))) {
            return (SecretKey) in.readObject();
        }
    }

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        if (publicKey instanceof PublicKey) {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } else {
            throw new IllegalArgumentException("Invalid key type. It must be PublicKey for RSA encryption.");
        }
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        if (privateKey instanceof PrivateKey) {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } else {
            throw new IllegalArgumentException("Invalid key type. It must be PrivateKey for RSA decryption.");
        }
        return cipher.doFinal(data);
    }

    public static byte[] hybridEncrypt(byte[] data, PublicKey publicKey) throws Exception {
        SecretKey symmetricKey = generateSecretKey();
    
        byte[] encryptedData = encrypt(data, symmetricKey);
        byte[] encryptedKey = encryptRSA(symmetricKey.getEncoded(), publicKey);
    
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedKey);
        outputStream.write(encryptedData);
    
        return outputStream.toByteArray();
    }
    
    public static byte[] hybridDecrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        int keyLength = 256; 
        byte[] encryptedKey = Arrays.copyOfRange(encryptedData, 0, keyLength);
        byte[] encryptedActualData = Arrays.copyOfRange(encryptedData, keyLength, encryptedData.length);
        byte[] decryptedKey = decryptRSA(encryptedKey, privateKey);
    
        SecretKey symmetricKey = new SecretKeySpec(decryptedKey, ALGORITHM);
    
        return decrypt(encryptedActualData, symmetricKey);
    }

    public static byte[] signMessage(String message, PrivateKey key) {

        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key); // Replace with your private key
            signature.update(message.getBytes());  // Assuming the message is "payment"
            return signature.sign();   
        }
        catch (SignatureException e){
            e.printStackTrace();
            return null;
        }
        catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
        catch (InvalidKeyException e){
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verifySignature(String message, byte[] signatureClient, PublicKey key) {

        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(key);
            signature.update(message.getBytes());  
            
            return signature.verify(signatureClient);
        }
        catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return false;
        }
        catch (InvalidKeyException e){
            e.printStackTrace();
            return false;
        }
        catch (SignatureException e){
            e.printStackTrace();
            return false;
        }
    }

    public static PublicKey getPublicKeyfromString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] byteKey = Base64.getDecoder().decode(key);
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(X509publicKey);
    }
}