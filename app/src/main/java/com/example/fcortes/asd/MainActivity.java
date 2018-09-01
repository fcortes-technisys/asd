package com.example.fcortes.asd;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.scottyab.aescrypt.AESCrypt;

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


        byte[] encodedBytes = Base64.encode(getHash("MDAyX0FDSWNobGtxWXI4eFFvQzhCMloxUFBhV2FjM0hKWGR2eDFPT1Z0U2VTL2hFSTBvOHIzdVRDTGFLbW1wYjAzK2M5Qkk5WVMrZ080UXkNCjM5d1c3MDlEcjJ1MUgvQi9SUjdKMGdjVjhON1hTNzQ9DQo"), Base64.DEFAULT);
        Log.i("encodedBytes " , new String(encodedBytes));


//        try {
//            String a = AESCrypt.encrypt("oAbzN3KKa3L3qt3ZeTRKVmwynZYUOOyr", "fer");
//            Log.i("AESCrypt " , a);
//
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }
//
//        byte[]  b = AES256Util.encrypt("oAbzN3KKa3L3qt3ZeTRKVmwynZYUOOyr", "0000000000000000", encodedBytes);
//        Log.i("AES256Util " , new String(b));


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
