package org.harryng.demo.user.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.harryng.demo.main.Application;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Calendar;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)
@Import(Application.class)
public class TestCryptoService {

    static Logger logger = LoggerFactory.getLogger(TestCryptoService.class);

    @Autowired
    private ApplicationContext applicationContext;

    @Before
    public void init() {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);
    }

    @Test
    public void testGcm() throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchProviderException {
        final int GCM_TAG_LENGTH = 16;
        Cipher cipherGcm = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher cipherCtr = Cipher.getInstance("AES/CTR/PKCS5Padding");
        String plainText = "abcdefghijklmnopqrstuvwxyz0123456789";
        byte[] plainTextBytes = plainText.getBytes("UTF-8");
        byte[] keyBin = {(byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
                (byte) 0xBB, (byte) 0xBB, (byte) 0xBB, (byte) 0xBB,
                (byte) 0xCC, (byte) 0xCC, (byte) 0xCC, (byte) 0xCC,
                (byte) 0xDD, (byte) 0xDD, (byte) 0xDD, (byte) 0xDD,
                (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
                (byte) 0xBB, (byte) 0xBB, (byte) 0xBB, (byte) 0xBB,
                (byte) 0xCC, (byte) 0xCC, (byte) 0xCC, (byte) 0xCC,
                (byte) 0xDD, (byte) 0xDD, (byte) 0xDD, (byte) 0xDD};
        byte[] ivBin = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        byte[] ivBin2 = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        SecretKey key = new SecretKeySpec(keyBin, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivBin);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBin2);

        cipherGcm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        cipherCtr.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] gcmCipherTextBin = cipherGcm.doFinal(plainTextBytes);
        byte[] ctrCipherTextBin = cipherCtr.doFinal(plainTextBytes);
        logger.info("GCM Cipher text:" + Hex.toHexString(gcmCipherTextBin));
        logger.info("CBC Cipher text:" + Hex.toHexString(ctrCipherTextBin));

        cipherGcm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        cipherCtr.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] gcmPlainTextBin = cipherGcm.doFinal(gcmCipherTextBin);
        byte[] ctrPlainTextBin = cipherCtr.doFinal(ctrCipherTextBin);
        logger.info("GCM Plain text:" + new String(gcmPlainTextBin));
        logger.info("CBC Plain text:Ø" + new String(ctrPlainTextBin));
    }

    @Test
    public void testECDH() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        final String engineName = "secp256r1";// secp384r1 secp512r1
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(engineName);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH");
        keyPairGenerator.initialize(ecGenParameterSpec);
        logger.info("=====");
    }

    @Test
    public void testPBKDF2() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        final String passwd = "1234";
        final int iterator = 10240;
        final int keyLen = 128;
        final byte[] salt = "0000".getBytes();
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(passwd.toCharArray(), salt, iterator, keyLen);
        long start = Calendar.getInstance().getTimeInMillis();
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        long finish = Calendar.getInstance().getTimeInMillis();
        logger.info("Secret Key:" + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        logger.info("Gen key in: " + (finish - start));
        logger.info("=====");
        Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] ivBin = {0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 1};
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(ivBin);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        logger.info("=====");
        String dataStr = "abcdefghijklmnopqrstuvwxyz0123456789";
        logger.info("Crypted data:" + Base64.getEncoder().encodeToString(aesCipher.doFinal(dataStr.getBytes())));
    }
}
