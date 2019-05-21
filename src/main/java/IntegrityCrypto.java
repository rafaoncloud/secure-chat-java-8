package main.java;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;


/**
 *  Message Authentication Code (MAC) algorithm - MAC provides a way to
 *  check the integrity of information transmitted over or stored in an
 *  unreliable medium, based on a secret key
 */
public class IntegrityCrypto
{
    public static final String ENCRYPTION_ALGORITHM = "AES";
    public static final String CRYPTOGRAPHY_HASH_FUNCTION = "HmacSHA256";

    public static byte[] generateMAC(byte[] message, byte[] key)
            throws InvalidKeyException, NoSuchAlgorithmException
    {
        // Makes use of a already existing shared key
        SecretKeySpec keySpec = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);

        Mac mac = Mac.getInstance(CRYPTOGRAPHY_HASH_FUNCTION);
        mac.init(keySpec);

        byte[] result = mac.doFinal(message);
        return result;
    }

    public static Boolean compareMAC(byte[] msg1, byte[] msg2)
    {
        try
        {
            if (!Arrays.equals(msg1, msg2))
                return false;
        }
        catch (Exception e)
        {
            System.out.println("The message is not integral!");
        }
        return true;
    }
}
