package main.java;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class SymmetricEncryption
{

    public static final int INITIALIZATION_VECTOR_SIZE = 16;
    public static final int KEY_SIZE = 192;
    public static final String ENCRYPTION_ALGORITHM = "AES";

    public static void main(String[] args)
    {
        SymmetricEncryption crypto1 = null;
        SymmetricEncryption crypto2 = null;

        System.out.println("[TEST] ------ Secret Message ------ [TEST]");
        System.out.println();
        try
        {
            crypto1 = new SymmetricEncryption();
            crypto2 = new SymmetricEncryption();

            Certification client1 = new Certification(1);
            Certification client2 = new Certification(2);

            String plaintext = "This is the secret message!";
            System.out.println("Plain Text: " + plaintext);
            System.out.println("Encrypting...");
            String ciphertext = crypto1.encrypt(plaintext, Certification.ALIAS_CLIENT_PUBLIC[1],
                    client1.sign(plaintext));
            System.out.println("All Cipher Text (Encrypted): " + ciphertext);

            System.out.println("Decrypting and checking Integrity (MAC)...");
            Message decrypted = crypto2.decrypt(ciphertext, client2);
            System.out.println("Plain Text: " + decrypted.getPlainText());
            System.out.println("Signature: " + decrypted.getSignature().toString());
            System.out.println("Alias (Identification): " + decrypted.getAliasPublic());


            System.out.println(decrypted);
        } catch (CertificateException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        } catch (InvalidKeyException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e)
        {
            e.printStackTrace();
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    public String encrypt(String plaintext, String aliasPublic, byte[] signature) throws BadPaddingException,
            InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException

    {
        return encrypt(generateIV(), plaintext, aliasPublic, signature);
    }

    private String encrypt(byte[] iv, String plaintext, String aliasPublic, byte[] signature)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            NoSuchPaddingException

    {
        byte[] decrypted = plaintext.getBytes("UTF-8");
        byte[] mac = IntegrityCrypto.generateMAC(decrypted, getKeyDecoded());
        byte[] encrypted = encrypt(iv, decrypted);
        byte[] alias = aliasPublic.getBytes("UTF-8");

        StringBuilder ciphertext = new StringBuilder();
        ciphertext.append(Base64.getEncoder().encodeToString(iv));
        ciphertext.append(":");
        ciphertext.append(Base64.getEncoder().encodeToString(encrypted));
        // INTEGRITY - MAC
        ciphertext.append(":");
        ciphertext.append(Base64.getEncoder().encodeToString(mac));
        // SIGNATURE
        ciphertext.append(":");
        ciphertext.append(Base64.getEncoder().encodeToString(alias));
        ciphertext.append(":");
        ciphertext.append(Base64.getEncoder().encodeToString(signature));
        return ciphertext.toString();
    }

    public Message decrypt(String ciphertext, Certification cert)
            throws NoSuchPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, UnsupportedEncodingException,
            KeyStoreException, SignatureException
    {
        String[] parts = ciphertext.split(":");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);
        byte[] decrypted = decrypt(iv, encrypted);
        byte[] mac1 = Base64.getDecoder().decode(parts[2]);

        // CHECK INTEGRITY OF THE MESSAGE
        byte[] mac2 = IntegrityCrypto.generateMAC(decrypted, getKeyDecoded());
        if (!IntegrityCrypto.compareMAC(mac1, mac2))
        {
            throw new RuntimeException("Integrity was compromised (Received MAC1 != Generated MAC) !!!");
        }

        // VERIFY SIGNATURE
        byte[] aliasPublic = Base64.getDecoder().decode(parts[3]);
        byte[] signature = Base64.getDecoder().decode(parts[4]);
        String aliasPublicStr = new String(aliasPublic);
        cert.verifySignature(decrypted, signature, aliasPublicStr);

        return new Message(decrypted, signature, aliasPublic);
    }

    private Key key;

    public SymmetricEncryption(Key key)
    {
        this.key = key;
    }

    public SymmetricEncryption()
            throws Exception
    {
        this(generateSymmetricKey());
    }

    public Key getKey()
    {
        return key;
    }

    public String getKeyEnconded()
    {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public byte[] getKeyDecoded()
    {
        return key.getEncoded();
    }

    public void setKey(Key key)
    {
        this.key = key;
    }

    public static byte[] generateIV()
    {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[INITIALIZATION_VECTOR_SIZE];
        random.nextBytes(iv);
        return iv;
    }

    public static Key generateSymmetricKey()
            throws Exception
    {
        KeyGenerator generator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        generator.init(KEY_SIZE);
        SecretKey key = generator.generateKey();
        return key;
    }

    private byte[] encrypt(byte[] iv, byte[] plaintext)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException

    {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    private byte[] decrypt(byte[] iv, byte[] ciphertext)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }
}