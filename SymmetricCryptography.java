import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class SymmetricCryptography 
{

    public static final int INITIALIZATION_VECTOR_SIZE = 16;
    public static final int KEY_SIZE = 192;
    public static final String ENCRYPTION_ALGORITHM = "AES";

    public static void main(String[] args) 
        throws Exception 
    {
        SymmetricCryptography crypto = new SymmetricCryptography();

        String plaintext = "[Test] Secret Message";
        System.out.println(plaintext);

        String ciphertext = crypto.encrypt(plaintext);
        System.out.println(ciphertext);

        String decrypted = crypto.decrypt(ciphertext);
        System.out.println(decrypted);
    }

    public String encrypt(String plaintext) 
        throws Exception 
    {
        return encrypt(generateIV(), plaintext);
    }

    public String encrypt(byte[] iv, String plaintext) 
        throws Exception 
    {
        byte[] decrypted = plaintext.getBytes();
        byte[] encrypted = encrypt( iv, decrypted );
        StringBuilder ciphertext = new StringBuilder();
        ciphertext.append(Base64.getEncoder().encodeToString(iv));
        ciphertext.append(":");
        ciphertext.append(Base64.getEncoder().encodeToString(encrypted));
        return ciphertext.toString();
    }

    public String decrypt(String ciphertext) 
        throws Exception 
    {
        String[] parts = ciphertext.split(":");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);
        byte[] decrypted = decrypt(iv, encrypted);

        return new String(decrypted);
    }

    private Key key;

    public SymmetricCryptography(Key key) 
    {
        this.key = key;
    }
    
    public SymmetricCryptography() 
        throws Exception 
    {
        this( generateSymmetricKey() );
    }

    public Key getKey() 
    {
        return key;
    }

    public void setKey(Key key) 
    {
        this.key = key;
    }

    public static byte[] generateIV() 
    {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte [INITIALIZATION_VECTOR_SIZE];
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
    
    public byte[] encrypt(byte[] iv, byte[] plaintext) 
        throws Exception 
    {
        Cipher cipher = Cipher.getInstance( key.getAlgorithm() + "/CBC/PKCS5Padding" );
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal( plaintext );
    }

    public byte[] decrypt(byte[] iv, byte[] ciphertext) 
        throws Exception 
    {
        Cipher cipher = Cipher.getInstance( key.getAlgorithm() + "/CBC/PKCS5Padding" );
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal( ciphertext );
    }
}


/*private SecretKeySpec secretKey;
private Cipher cipher;

public SymmetricKeyExample(String secret, int length, String algorithm)
throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException 
{
	byte[] key = new byte[length];
	key = fixSecret(secret, length);
	this.secretKey = new SecretKeySpec(key, algorithm);
	this.cipher = Cipher.getInstance(algorithm);
}

private byte[] fixSecret(String s, int length) 
	throws UnsupportedEncodingException 
{
    if (s.length() < length) 
    {
		int missingLength = length - s.length();
        for (int i = 0; i < missingLength; i++) 
        {
			s += " ";
		}
	}
	return s.substring(0, length).getBytes("UTF-8");
}

public void encryptFile(File f)
        throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException 
{
	System.out.println("Encrypting file: " + f.getName());
	this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
	this.writeToFile(f);
}

public void decryptFile(File f)
        throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException 
{
	System.out.println("Decrypting file: " + f.getName());
	this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
	this.writeToFile(f);
}

public void writeToFile(File f) throws IOException, IllegalBlockSizeException, BadPaddingException 
{
	FileInputStream in = new FileInputStream(f);
	byte[] input = new byte[(int) f.length()];
	in.read(input);

	FileOutputStream out = new FileOutputStream(f);
	byte[] output = this.cipher.doFinal(input);
	out.write(output);

	out.flush();
	out.close();
	in.close();
}

public static void main(String[] args) 
{
	File dir = new File("src/symmetricKey");
	File[] filelist = dir.listFiles();

	SymmetricKeyExample ske;
	try {
		ske = new SymmetricKeyExample("!@#$MySecr3tPassw0rd", 16, "AES");

		int choice = -2;
		while (choice != -1) {
			String[] options = { "Encrypt All", "Decrypt All", "Exit" };
			choice = JOptionPane.showOptionDialog(null, "Select an option", "Options", 0,
					JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

			switch (choice) {
			case 0:
				Arrays.asList(filelist).forEach(file -> {
					try {
						ske.encryptFile(file);
					} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
							| IOException e) {
						System.err.println("Couldn't encrypt " + file.getName() + ": " + e.getMessage());
					}
				});
				System.out.println("Files encrypted successfully");
				break;
			case 1:
				Arrays.asList(filelist).forEach(file -> {
					try {
						ske.decryptFile(file);
					} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
							| IOException e) {
						System.err.println("Couldn't decrypt " + file.getName() + ": " + e.getMessage());
					}
				});
				System.out.println("Files decrypted successfully");
				break;
			default:
				choice = -1;
				break;
			}
		}
	} catch (UnsupportedEncodingException ex) {
		System.err.println("Couldn't create key: " + ex.getMessage());
	} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
		System.err.println(e.getMessage());
    }
}*/