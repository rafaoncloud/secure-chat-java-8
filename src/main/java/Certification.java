package main.java;

import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class Certification
{
    public static final String TRUST_MANAGER_ALGORITHM = "SunX509";
    public static final String KEYSTORE_TYPE = "JKS";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String SERVER_STORE_JKS = "key-pairs/plainserver.jks";
    public static final String SERVER_STORE_PASSWORD = "password";
    public static final String ALIAS = "plainserverkeys";
    public static final String ALIAS_PUBLIC = "serverpub";
    public static final String[] CLIENTS_KEYS = {"key-pairs/plainclient.jks", "key-pairs/plainclient2.jks"};
    public static final String[] CLIENTS_PUBLIC_KEYS = {"key-pairs/clientpub.jks", "key-pairs/clientpub2.jks"};
    public static final String[] CLIENTS_STORE_PASSWORDS = {"password", "password"};
    public static final String[] ALIAS_CLIENT = {"plainclientkeys", "plainclientkeys2"};
    public static final String[] ALIAS_CLIENT_PUBLIC = {"clientpub", "clientpub2"};

    private KeyStore serverKeystore = null;

    private KeyStore[] clientsStores = null; // Client
    private KeyStore clientStore = null; // Server


    private Signature signer = null;
    private String myPublicAlias = null;


    public Certification() // Server
            throws CertificateException, NoSuchAlgorithmException,
            KeyStoreException, IOException, UnrecoverableEntryException,
            InvalidKeyException
    {
        setUpServer();
        myPublicAlias = ALIAS_PUBLIC;
    }

    public Certification(int clientID) // Client
            throws CertificateException, NoSuchAlgorithmException,
            KeyStoreException, InvalidKeyException,
            IOException, UnrecoverableEntryException
    {
        myPublicAlias = ALIAS_CLIENT_PUBLIC[clientID - 1];
        setUpClient(clientID);
    }

    private void setUpServer()
            throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException,
            UnrecoverableEntryException, InvalidKeyException
    {
        FileInputStream fileInputStream = null;

        serverKeystore = KeyStore.getInstance(KEYSTORE_TYPE);

        // Load Key Store
        fileInputStream = new FileInputStream(SERVER_STORE_JKS);
        serverKeystore.load(fileInputStream, SERVER_STORE_PASSWORD.toCharArray());
        fileInputStream.close();

        // Read Server Private Key
        KeyStore.ProtectionParameter protectionParameter =
                new KeyStore.PasswordProtection(SERVER_STORE_PASSWORD.toCharArray());
        KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) serverKeystore.getEntry(ALIAS,
                protectionParameter);
        PrivateKey privateKey = privKeyEntry.getPrivateKey();

        // Initialize signature
        signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(privateKey);

        // Read client keys
        int numCli = CLIENTS_PUBLIC_KEYS.length;
        clientsStores = new KeyStore[numCli];
        TrustManagerFactory trustManager = null;
        for (int i = 0; i < numCli; i++)
        {
            FileInputStream fileInStream = new FileInputStream(CLIENTS_PUBLIC_KEYS[i]);
            clientsStores[i] = KeyStore.getInstance(KEYSTORE_TYPE);
            clientsStores[i].load(fileInStream, CLIENTS_STORE_PASSWORDS[i].toCharArray());
            trustManager = TrustManagerFactory.getInstance(TRUST_MANAGER_ALGORITHM);
            trustManager.init(clientsStores[i]);
        }
    }

    private void setUpClient(int clientID)
            throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, UnrecoverableEntryException
    {
        int id = clientID - 1;

        // Calls new client
        clientStore = KeyStore.getInstance(KEYSTORE_TYPE);

        FileInputStream fileInputStream = new FileInputStream(CLIENTS_KEYS[id]);
        clientStore.load(fileInputStream, CLIENTS_STORE_PASSWORDS[id].toCharArray());
        fileInputStream.close();

        KeyStore.ProtectionParameter entryPassword =
                new KeyStore.PasswordProtection(CLIENTS_STORE_PASSWORDS[id].toCharArray());
        KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) clientStore.getEntry(ALIAS_CLIENT[id],
                entryPassword);
        PrivateKey privateKey = privKeyEntry.getPrivateKey();
        signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(privateKey);

        serverKeystore = KeyStore.getInstance(KEYSTORE_TYPE);
        serverKeystore.load(new FileInputStream(SERVER_STORE_JKS), SERVER_STORE_PASSWORD.toCharArray());
        TrustManagerFactory trustManager = TrustManagerFactory.getInstance(TRUST_MANAGER_ALGORITHM);
        trustManager.init(serverKeystore);
        Enumeration<String> e = serverKeystore.aliases();
        System.out.print("[LOG] Alias in KeyStore:");
        while(e.hasMoreElements())
        {
            System.out.print(" " + e.nextElement());
        }
        System.out.println();
    }

    public boolean verifySignature(byte[] plainText, byte[] signature, String aliasPublic)
            throws UnsupportedEncodingException, KeyStoreException
            , NoSuchAlgorithmException, InvalidKeyException,
            SignatureException
    {
        boolean isValid = false;
        KeyStore keyStore = serverKeystore;

        if (!keyStore.containsAlias(aliasPublic))
        {
            System.out.println("[LOG] The alias " + aliasPublic + " is not in the key store!");
        }

        Certificate publicCert = keyStore.getCertificate(aliasPublic);
        Signature verifySignature = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifySignature.initVerify(publicCert.getPublicKey());
        verifySignature.update(plainText);

        isValid = verifySignature.verify(signature);

        if (!isValid)
        {
            System.out.println("[LOG] The verified signature from [" + aliasPublic + "] is not valid!");
            System.exit(1); // This is not supposed to do in a real program (The resources must be closed)
        }

        return true;
    }

    public byte[] sign(String plainText)
            throws UnsupportedEncodingException, SignatureException
    {
        byte[] text = plainText.getBytes("UTF-8");
        //Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        //signer.initSign();
        signer.update(text);
        return signer.sign();
    }

    public String getMyPublicAlias()
    {
        return myPublicAlias;
    }
}
