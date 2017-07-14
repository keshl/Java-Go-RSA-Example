package xyz.dmester.rsa_client;

import android.util.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SocketManager {
    private Socket socket;
    private OutputStream dataOutputStream;
    private InputStream dataInputStream;
    private KeyPair keyPair;
    private PublicKey serverKey;
    String publicPEM;
    private String error = "Go Rules!";

    SocketManager(String host, int port) {
        try {
            socket = new Socket(host, port);
            dataOutputStream = socket.getOutputStream();
            dataInputStream = socket.getInputStream();
        } catch (Exception e) {
            error = "Connection error: " + e.getMessage();
            socket = null;
        }
    }

    public String getError() {
        return error;
    }

    public boolean isConnected() {
        return socket != null;
    }

    public boolean isEncrypted() {
        return keyPair != null;
    }

    private void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        keyPair = keyPairGenerator.generateKeyPair();
    }

    private void prepareKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] pub = new byte[2048];

        // creating my public key
        byte[] data = keyPair.getPublic().getEncoded();
        publicPEM = "-----BEGIN PUBLIC KEY-----\n"+new String(Base64.encode(data, Base64.DEFAULT))+"-----END PUBLIC KEY-----";

        try {
            // Reading server public key
            int n = dataInputStream.read(pub);

            String key = new String(pub, 0, n);
            key = key.replace("-----BEGIN PUBLIC KEY-----\n", "");
            key = key.replace("-----END PUBLIC KEY-----\n", "");

            byte [] decoded = org.spongycastle.util.encoders.Base64.decode(key);

            X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(decoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            serverKey = kf.generatePublic(spec);

            // sending my public key
            dataOutputStream.write(publicPEM.getBytes());
        } catch (IOException e) {
            error = e.getMessage();
            publicPEM = null;
        }
    }

    public void encryptConnection() {
        try {
            generateKeys();
            prepareKeys();
        } catch (NoSuchAlgorithmException e) {
            error = "NoSuchAlgorithm: " + e.getMessage();
            keyPair = null;
        } catch (InvalidKeySpecException e) {
            error = "InalidKeySpec: " + e.getMessage();
            keyPair = null;
        } catch (IOException e) {
            error = "IOException: "+e.getMessage();
            keyPair = null;
        }
    }

    public boolean send(String str) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher.init(Cipher.ENCRYPT_MODE, serverKey);
            byte[] text = cipher.doFinal(str.getBytes());

            dataOutputStream.write(text);

        } catch (IOException e) {
            error = e.getMessage();
            return false;
        } catch (NoSuchPaddingException e) {
            error = e.getMessage();
            return false;
        } catch (NoSuchAlgorithmException e) {
            error = e.getMessage();
            return false;
        } catch (InvalidKeyException e) {
            error = e.getMessage();
            return false;
        } catch (BadPaddingException e) {
            error = e.getMessage();
            return false;
        } catch (IllegalBlockSizeException e) {
            error = e.getMessage();
            return false;
        }

        return true;
    }

    public String read() {
        String ret;
        byte[] data = new byte[256];

        try {
            int n = dataInputStream.read(data);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] text = cipher.doFinal(data);

            ret = new String(text);

        } catch (IOException e) {
            error = "IO:"+e.getMessage();
            return null;
        } catch (NoSuchAlgorithmException e) {
            error = e.getMessage();
            return null;
        } catch (InvalidKeyException e) {
            error = e.getMessage();
            return null;
        } catch (NoSuchPaddingException e) {
            error = e.getMessage();
            return null;
        } catch (BadPaddingException e) {
            error = e.getMessage();
            return null;
        } catch (IllegalBlockSizeException e) {
            error = e.getMessage();
            return null;
        }

        return ret;
    }
}
