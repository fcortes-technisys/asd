package com.example.fcortes.asd;

import android.provider.SyncStateContract;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.scottyab.aescrypt.AESCrypt;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import github.didikee.aes256cbc.AES256Util;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // encriptacion de pass

        byte[] encodedBytes = Base64.encode(getHash("MDAyX0FDSWNobGtxWXI4eFFvQzhCMloxUFBhV2FjM0hKWGR2eDFPT1Z0U2VTL2hFSTBvOHIzdVRDTGFLbW1wYjAzK2M5Qkk5WVMrZ080UXkNCjM5d1c3MDlEcjJ1MUgvQi9SUjdKMGdjVjhON1hTNzQ9DQo"), Base64.DEFAULT);
        Log.i("encodedBytes " , new String(encodedBytes));
        String key = new String(encodedBytes);
        Log.i("encodedBytes key" , key);



        byte[]  b = new byte[0];
        try {
            b = AES256Util.encrypt(key.substring(0, 32), "0000000000000000", "user_password".getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Log.i("AES256Util encoded" , new String(Base64.encode(b, Base64.DEFAULT)));
        String encoded = new String(Base64.encode(b, Base64.DEFAULT));


        // decriptacion ?

        try {
            String encrytedData = encrytData("user_password", key.substring(0, 32));
            Log.i("AES256Util encoded" , encrytedData);
            Log.i("AES256Util decoded" , decryptData(encrytedData, key.substring(0, 32)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrytData(String text, String key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        byte[] static_key = key.getBytes("UTF-8");

        SecretKeySpec keySpec = new SecretKeySpec(static_key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("0000000000000000".getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] results = cipher.doFinal(text.getBytes());

        return Base64.encodeToString(results, Base64.NO_WRAP);

    }

    public static String decryptData(String text, String key) throws Exception{

        byte[] encryted_bytes = Base64.decode(text, Base64.DEFAULT);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        byte[] static_key = key.getBytes("UTF-8");

        SecretKeySpec keySpec = new SecretKeySpec(static_key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("0000000000000000".getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encryted_bytes);
        String result = new String(decrypted);

        return result;
    }

    public byte[] getHash(String password) {
        MessageDigest digest=null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
        digest.reset();
        return digest.digest(password.getBytes());
    }
}
