import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.*;
import java.security.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
 
import javax.crypto.Cipher;
 
// Java 8 example for RSA encryption/decryption.
// Uses strong encryption with 2048 key size.
public class AsymmetricCryptography 
{
 
    public static void main(String[] args) throws Exception {
        String plainText = "Hello World!";
 
        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();
 
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");
 
        String encryptedText = encryptMessage(plainText, privateKey);
        String descryptedText = decryptMessage(encryptedText, publicKey);
 
        System.out.println("input:" + plainText);
        System.out.println("encrypted:" + encryptedText);
        System.out.println("decrypted:" + descryptedText);
 
    }
 
    // Get RSA keys. Uses key size of 2048.
    private static Map<String,Object> getRSAKeys() 
        throws Exception 
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
 
    // Decrypt using RSA public key
    private static String decryptMessage(String encryptedText, PublicKey publicKey) 
        throws Exception 
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
 
    // Encrypt using RSA private key
    private static String encryptMessage(String plainText, PrivateKey privateKey) 
        throws Exception 
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}


/*
public class AsymmetricCryptography 
{
    // ------------------ Confidentiality ----------------- 
    // --------------- Asymmetric Encryption -------------- 
    private Cipher cipher;

    public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException 
    {
		this.cipher = Cipher.getInstance("RSA");
	}

    public PrivateKey getPrivate(String filename) throws Exception 
    {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

    public PublicKey getPublic(String filename) throws Exception 
    {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public void encryptFile(byte[] input, File output, PrivateKey key) 
        throws IOException, GeneralSecurityException 
    {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	public void decryptFile(byte[] input, File output, PublicKey key) 
        throws IOException, GeneralSecurityException 
    {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	private void writeToFile(File output, byte[] toWrite)
            throws IllegalBlockSizeException, BadPaddingException, IOException 
    {
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}

	public String encryptText(String msg, PrivateKey key) 
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, 
            BadPaddingException, InvalidKeyException 
    {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	public String decryptText(String msg, PublicKey key)
			throws InvalidKeyException, UnsupportedEncodingException, 
            IllegalBlockSizeException, BadPaddingException 
    {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
	}

    public byte[] getFileInBytes(File f) throws IOException 
    {
		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		fis.read(fbytes);
		fis.close();
		return fbytes;
	}

    public static void main(String[] args) throws Exception 
    {
		AsymmetricCryptography ac = new AsymmetricCryptography();
		PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey");
		PublicKey publicKey = ac.getPublic("KeyPair/publicKey");

		String msg = "Cryptography is fun!";
		String encrypted_msg = ac.encryptText(msg, privateKey);
		String decrypted_msg = ac.decryptText(encrypted_msg, publicKey);
		System.out.println("Original Message: " + msg + 
			"\nEncrypted Message: " + encrypted_msg
			+ "\nDecrypted Message: " + decrypted_msg);

		if (new File("KeyPair/text.txt").exists()) {
			ac.encryptFile(ac.getFileInBytes(new File("KeyPair/text.txt")), 
				new File("KeyPair/text_encrypted.txt"),privateKey);
			ac.decryptFile(ac.getFileInBytes(new File("KeyPair/text_encrypted.txt")),
				new File("KeyPair/text_decrypted.txt"), publicKey);
		} else {
			System.out.println("Create a file text.txt under folder KeyPair");
		}
	}
}
*/