import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeyPair {

	private KeyPairGenerator keyGen;
	private KeyPair pair;
	private PrivateKey privateKey;
	private PublicKey publicKey;

    public GenerateKeyPair(int keylength) 
        throws NoSuchAlgorithmException, NoSuchProviderException 
    {
		this.keyGen = KeyPairGenerator.getInstance("RSA");
		this.keyGen.initialize(keylength);
	}

    public void createKeys() 
    {
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

    public PrivateKey getPrivateKey() 
    {
		return this.privateKey;
	}

    public PublicKey getPublicKey() 
    {
		return this.publicKey;
	}

    public void writeToFile(String path, byte[] key) throws IOException 
    {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}

    public static void main(String[] args) 
    {
        if (args.length != 1)
            		// Displays correct usage for server
            		System.out.println("Usage: java GenerateKeys <key-id>");    
        else
        {
            String publicKeyName = "KeyPair/publicKey" + args[0];
            String privateKeyName = "KeyPair/privateKey" + args[0];
            GenerateKeyPair genKey;

            try {
                genKey = new GenerateKeyPair(1024); // Key-length
                genKey.createKeys();
                genKey.writeToFile(publicKeyName, genKey.getPublicKey().getEncoded());
                genKey.writeToFile(privateKeyName, genKey.getPrivateKey().getEncoded());
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                System.err.println(e.getMessage());
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
        }
	}
}