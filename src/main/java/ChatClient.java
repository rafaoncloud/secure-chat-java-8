package main.java;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.util.Base64;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;

    // Added - Cryptography
    private SymmetricEncryption crypt = null;

    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);

            start();
        }
        
        catch(UnknownHostException uhe)
        {  
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        }
      
        catch(IOException ioexception)
        {  
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage()); 
        }
        
   }
    
   public void run()
   {
       String msg = null;

       while (thread != null)
       {  
           try
           {
               // Added - Encrypt Message
               msg = console.readLine();
               String encryptedMsg = crypt.encrypt(msg);

               // Sends message from console to server
               streamOut.writeUTF(encryptedMsg);
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           } catch (Exception e) {
               e.printStackTrace();
           }
       }
   }
    
    
    public void handle(String msg)
    {
        // Added - Decrypted Message
        String decryptedMsg = null;
        try {
            decryptedMsg = crypt.decrypt(msg);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Receives message from server
        if (msg.equals(".quit"))
        {
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(decryptedMsg);
    }
    
    // Inits new client thread
    public void start() throws IOException
    {
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());

        if (thread == null)
        {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop()
    {
        if (thread != null)
        {
            thread.stop();
            thread = null;
        }
        try
        {
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();
        }

        catch(IOException ioe)
        {
            System.out.println("Error closing thread...");
        }
        client.close();
        client.stop();
    }

    public void installKey(String msg)
    {
        String encodedKey = msg;

        // Cryptography - Added
        System.out.println("[LOG] Receiving first message and setting up Symmetric Encryption...");

        // Decode the base64 encoded string (key)
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        System.out.println("[LOG] Installing Key...");
        crypt = new SymmetricEncryption(key);
    }

    
    public static void main(String args[])
    {  
        ChatClient client = null;
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }
    
}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {  
        client   = _client;
        socket   = _socket;
        open();  
        start();
    }
   
    public void open()
    {  
        try
        {  
            streamIn  = new DataInputStream(socket.getInputStream());
        }
        catch(IOException ioe)
        {  
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }
    
    public void close()
    {  
        try
        {  
            if (streamIn != null) streamIn.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing input stream: " + ioe);
        }
    }
    
    public void run()
    {
        try {
            // Added - Cryptography
            client.installKey(streamIn.readUTF());

            System.out.println("-------- Welcome --------");
            while (true)
            {
                client.handle(streamIn.readUTF());
            }
        }
        catch(IOException ioe)
        {
            System.out.println("Listening error: " + ioe.getMessage());
            client.stop();
        }
    }
}

