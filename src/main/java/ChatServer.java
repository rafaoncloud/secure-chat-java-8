package main.java;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class ChatServer implements Runnable
{
    public static final int MAX_CLIENTS = 20;

    private ChatServerThread clients[] = new ChatServerThread[MAX_CLIENTS];
    private ServerSocket server_socket = null;
    private Thread thread = null;
    private int clientCount = 0;

    // Added - Access Control
    private boolean hasAccessControl = false;
    private List<String> refusedAddrs = null;

    // Added - Cryptography
    SymmetricEncryption[] crypt = new SymmetricEncryption[MAX_CLIENTS];

    //Added - Signature
    Certification cert = null;

    public ChatServer(int port, boolean hasAccessControl, List<String> refusedAddrs)
    {
        // Drops connection coming from certain addresses
        if (hasAccessControl)
        {
            this.hasAccessControl = hasAccessControl;
            this.refusedAddrs = refusedAddrs;
        }

        try
        {
            System.out.println("[LOG] Reading up certification key stores and set up signature");
            cert = new Certification();

            // Binds to port and starts server
            System.out.println("Binding to port " + port);
            server_socket = new ServerSocket(port);
            System.out.println("Server started: " + server_socket);
            start();
        } catch (IOException ioexception)
        {
            // Error binding to port
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        } // Added
        catch (CertificateException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (InvalidKeyException e)
        {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e)
        {
            e.printStackTrace();
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        }
    }

    public void run()
    {
        while (thread != null)
        {
            try
            {
                // Adds new thread for new client
                System.out.println("Waiting for a client ...");
                addThread(server_socket.accept());
            } catch (IOException ioexception)
            {
                System.out.println("Accept error: " + ioexception);
                stop();
            } catch (Exception e)
            {
                // Added
                e.printStackTrace();
            }
        }
    }

    public void start()
    {
        if (thread == null)
        {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop()
    {
        if (thread != null)
        {
            // Stops running thread for client
            thread.stop();
            thread = null;
        }
    }

    private int findClient(int ID)
    {
        // Returns client from id
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }

    public synchronized void handle(int ID, String input)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException,
            UnsupportedEncodingException, KeyStoreException, IllegalBlockSizeException
    {
        // Added - Decrypt message with the correspondent client Key
        int clientIndex = findClient(ID);
        Message decryptedMsg = crypt[clientIndex].decrypt(input, cert);
        String encryptedMsg = null;

        if (decryptedMsg.equals(".quit"))
        {
            int leaving_id = clientIndex;
            // Client exits
            clients[leaving_id].send(".quit");
            // Notify remaing users
            for (int i = 0; i < clientCount; i++)
            {
                if (i != leaving_id)
                {
                    // Added - Encrypt message with the correspondent client key
                    String msg = "Client " + ID + "[" + decryptedMsg.getAliasPublic() + "] exits.";
                    System.out.println(msg);
                    encryptedMsg = crypt[i].encrypt(msg, Certification.ALIAS, cert.sign(msg));
                    clients[i].send(encryptedMsg);
                }
            }
            remove(ID);
        } else
        {
            // Brodcast message for every other client online
            for (int i = 0; i < clientCount; i++)
            {
                // Added - Encrypt message with the correspondent client key
                String msg = ID + " [" + decryptedMsg.getAliasPublic() + "]: " + decryptedMsg.getPlainText();
                System.out.println(msg);
                encryptedMsg = crypt[i].encrypt(msg, Certification.ALIAS, cert.sign(msg));
                clients[i].send(encryptedMsg);
            }
        }
    }

    public synchronized void remove(int ID)
    {
        int pos = findClient(ID);

        if (pos >= 0)
        {
            // Removes thread for exiting client
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1)
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            clientCount--;

            try
            {
                toTerminate.close();
            } catch (IOException ioe)
            {
                System.out.println("Error closing thread: " + ioe);
            }

            toTerminate.stop();
        }
    }

    private void addThread(Socket socket)
            throws Exception
    {
        if (hasAccessControl)
        {
            String clientAddr = socket.getInetAddress().getHostAddress().trim();

            for (String refusedAddr : refusedAddrs)
            {
                if (refusedAddr.equalsIgnoreCase(clientAddr))
                {
                    System.out.println("[LOG] The IP " + refusedAddr + " is in the black-list. The " +
                            "connection with " + clientAddr + " is dropped...");
                    if (socket != null)
                        socket.close();
                }
            }
        }

        if (clientCount < clients.length)
        {
            // Adds thread for new accepted client
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);

            System.out.println("[LOG] Generating Symmetric Key..."); // Added
            crypt[clientCount] = new SymmetricEncryption(); // Added

            try
            {
                clients[clientCount].open();
                clients[clientCount].start();
                clientCount++;
            } catch (IOException ioe)
            {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }


    public static void main(String args[])
    {
        ChatServer server = null;
        List<String> accessControl = null;

        if (args.length < 1)
            // Displays correct usage for server
            System.out.println("Usage: java ChatServer port");
        else if (args.length >= 1)
        {
            if (args.length == 1)
            {
                // Calls new server
                server = new ChatServer(Integer.parseInt(args[0]), false, null);
            } else
            {
                // The remaining arguments are connections refused by their source IPs
                accessControl = new ArrayList<>();
                System.out.print("[LOG] The messages coming from the following source addresses " +
                        "will be dropped:");
                for (int i = 1; i < args.length; i++)
                {
                    System.out.println(" " + args[i]);
                    accessControl.add(args[i]);
                }
                // Calls new server
            }
            server = new ChatServer(Integer.parseInt(args[0]), true, accessControl);
        }
    }

    // Added
    public void sendCryptKey(int ID)
    {
        int clientIndex = findClient(ID);

        // Get base64 encoded version of the key
        String encodedKey = Base64.getEncoder().encodeToString(crypt[clientIndex].getKey().getEncoded());

        clients[clientIndex].send(encodedKey);
    }
}

class ChatServerThread extends Thread
{
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;


    public ChatServerThread(ChatServer _server, Socket _socket)
    {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
    }

    // Sends message to client
    public void send(String msg)
    {
        try
        {
            streamOut.writeUTF(msg);
            streamOut.flush();
        } catch (IOException e)
        {
            System.out.println(ID + " ERROR sending message: " + e.getMessage());
            server.remove(ID);
            stop();
            e.printStackTrace();
        }
    }

    // Gets id for client
    public int getID()
    {
        return ID;
    }

    // Runs thread
    public void run()
    {
        System.out.println("Server Thread " + ID + " running.");

        System.out.println("[LOG] Sending Key to Client " + ID + "...");
        server.sendCryptKey(ID);

        while (true)
        {
            try
            {
                server.handle(ID, streamIn.readUTF());
            } catch (UnsupportedEncodingException e)
            {
                e.printStackTrace();
            } catch (InvalidKeyException e)
            {
                e.printStackTrace();
            } catch (KeyStoreException e)
            {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e)
            {
                e.printStackTrace();
            } catch (SignatureException e)
            {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e)
            {
                e.printStackTrace();
            } catch (BadPaddingException e)
            {
                e.printStackTrace();
            } catch (NoSuchPaddingException e)
            {
                e.printStackTrace();
            } catch (IOException e)
            {
                System.out.println(ID + " ERROR reading: " + e.getMessage());
                server.remove(ID);
                stop();
                e.printStackTrace();
            }
        }
    }


    // Opens thread
    public void open() throws IOException
    {
        streamIn = new DataInputStream(new
                BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));
    }

    // Closes thread
    public void close() throws IOException
    {
        if (socket != null)
            socket.close();
        if (streamIn != null)
            streamIn.close();
        if (streamOut != null)
            streamOut.close();
    }

}

