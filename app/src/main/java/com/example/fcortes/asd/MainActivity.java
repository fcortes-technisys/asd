package com.example.fcortes.asd;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            Log.i("lala aaaaaaaaaa " , new String(Base64.encode(encrypt("1234", "9f3SlY6tPLYW429RHrAJUsFSpIDS0QowTue Sep 04 16:58:26 GMT-03:00 2018"), Base64.DEFAULT)));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // encriptacion de pass

        byte[] encodedBytes = getHash("9f3SlY6tPLYW429RHrAJUsFSpIDS0QowTue Sep 04 16:58:26 GMT-03:00 2018");
        Log.i("lala encodedBytes " , new String(encodedBytes));
        String key = new String(encodedBytes);
        Log.i("lala encodedBytes key" , String.valueOf(encodedBytes.length));


//        byte[]  b = new byte[0];
//        try {
//            b = AES256Util.encrypt(key.substring(0, 32), "0000000000000000", "user_password".getBytes("UTF-8"));
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//        Log.i("AES256Util encoded" , new String(Base64.encode(b, Base64.DEFAULT)));
//        String encoded = new String(Base64.encode(b, Base64.DEFAULT));


        // decriptacion ?

        try {
            String encrytedData = encrytData("1234", encodedBytes);
            Log.i("lala AES256Util encoded" , encrytedData);
            Log.i("lala AES256Util decoded" , decryptData(encrytedData, encodedBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrytData(String text,  byte[] encodedBytes) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        byte[] static_key = key.getBytes("UTF-8");

        SecretKeySpec keySpec = new SecretKeySpec(encodedBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("0000000000000000".getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] results = cipher.doFinal(text.getBytes("UTF-8"));

//        return new String(results);
        return new String(Base64.encode(results, Base64.DEFAULT));

    }

    public static String decryptData(String text, byte[] key) throws Exception{

        byte[] encryted_bytes = Base64.decode(text, Base64.DEFAULT);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
//        byte[] static_key = key.getBytes("UTF-8");

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("0000000000000000".getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encryted_bytes);
        String result = new String(decrypted);

        return result;
    }

    public byte[] getHash(String password) {
        byte[] keyBytes = null;
        try {
            int keySize = 32;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(password.getBytes("UTF-8"));
            keyBytes = new byte[keySize];
            System.arraycopy(Base64.encode(digest.digest(), Base64.DEFAULT), 0, keyBytes, 0, 32);

        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e1) {
            e1.printStackTrace();
        }


        return keyBytes;
    }




    public static byte[] encrypt(String plainText, String key) throws Exception {
        byte[] clean = plainText.getBytes();

        int ivSize = 16;
        int keySize = 32;

        // Generating IV.
        byte[] iv = new byte[ivSize];
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing key.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[keySize];

        System.arraycopy(Base64.encode(digest.digest(), Base64.DEFAULT), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        return encrypted;
    }

}
