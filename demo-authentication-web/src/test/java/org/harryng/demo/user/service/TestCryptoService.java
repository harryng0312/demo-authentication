package org.harryng.demo.user.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.harryng.demo.main.Application;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.HexFormat;

//@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)
//@Import(Application.class)
public class TestCryptoService {

    static Logger logger = LoggerFactory.getLogger(TestCryptoService.class);

    @Autowired
    private ApplicationContext applicationContext;

    @BeforeEach
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

    @Test
    public void testGenerateKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
        logger.info("Java generate an EC keypair");
        String ecdhCurvenameString = "secp256r1";
        // standard curvennames
        // secp256r1 [NIST P-256, X9.62 prime256v1]
        // secp384r1 [NIST P-384]
        // secp521r1 [NIST P-521]

        final byte[] seedArr = "01f82bfb2f0a3e988adc3d053d8e6ff878154306e402d871b7d6000823a1397f".getBytes();
//        ECPoint point = new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecParameterSpec = new ECGenParameterSpec(ecdhCurvenameString);

//        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
//        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
//        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(point, ecParameters);
//        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecParameters);

        final Provider provider = new BouncyCastleProvider();

        final SecureRandom secureRandom = SecureRandom.getInstance("DRBG");
//        final SecureRandom secureRandom = SecureRandom.getInstance("DEFAULT", provider);
        secureRandom.setSeed(seedArr);
        keyPairGenerator.initialize(ecParameterSpec, secureRandom);
//        keyPairGenerator.initialize(ecParameterSpec);
        KeyPair ecdhKeyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = ecdhKeyPair.getPrivate();
        PublicKey publicKey = ecdhKeyPair.getPublic();
        logger.info("privateKey: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        logger.info("publicKey: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    @Test
    public void testKeyAgreement() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        final String userPasswd = "P@ssw0rd";
        final byte[] secretSeed = "0123456789abcdef".getBytes();
        final String ecdhCurveName = "secp256k1";
//        final String ecdhCurveName = "secp256r1";
        // client side
        final KeyPairGenerator clientKeyPairGenerator = KeyPairGenerator.getInstance("EC");
        final ECGenParameterSpec clientEcParamSpec = new ECGenParameterSpec(ecdhCurveName);
        final KeyPair clientKeyPair = clientKeyPairGenerator.generateKeyPair();
        final PrivateKey clientPriKey = clientKeyPair.getPrivate();
        final PublicKey clientPubKey = clientKeyPair.getPublic();
        final byte[] clientPubKeyBytes = clientPubKey.getEncoded();
        logger.info("client PublicKey:" + HexFormat.of().formatHex(clientPubKey.getEncoded()));

        // server side
        final SecureRandom serverRand = SecureRandom.getInstance("DRBG");
        final var sessionIdBytes = new byte[20];
        final var randomNoBytes = new byte[20];
        serverRand.nextBytes(sessionIdBytes);
        serverRand.nextBytes(randomNoBytes);
        final String sessionId = HexFormat.of().formatHex(sessionIdBytes);
        final String randomNo = HexFormat.of().formatHex(randomNoBytes);

        final KeyPairGenerator serverKeyPairGenerator = KeyPairGenerator.getInstance("EC");
        final ECGenParameterSpec serverEcParamSpec = new ECGenParameterSpec(ecdhCurveName);
        final KeyPair serverKeyPair = serverKeyPairGenerator.generateKeyPair();
        final PrivateKey serverPriKey = serverKeyPair.getPrivate();
        final PublicKey serverPubKey = serverKeyPair.getPublic();
        final byte[] serverPubKeyBytes = serverPubKey.getEncoded();

        // after client sent to server, run on server:
        final KeyFactory serverKeyFactory = KeyFactory.getInstance("EC");
        final EncodedKeySpec clientPubKey2Spec = new X509EncodedKeySpec(clientPubKeyBytes);
        final PublicKey clientPubKey2 = serverKeyFactory.generatePublic(clientPubKey2Spec);
        logger.info("client PublicKey sent to server:" + HexFormat.of().formatHex(clientPubKey2.getEncoded()));
        final KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("ECDH");
        serverKeyAgreement.init(serverPriKey);
        serverKeyAgreement.doPhase(clientPubKey2, true);
        byte[] serverSecretKeyBytes = serverKeyAgreement.generateSecret();
        logger.info("SecretKey on server:" + HexFormat.of().formatHex(serverSecretKeyBytes));

        // after server returned to client
        final KeyFactory clientKeyFactory = KeyFactory.getInstance("EC");
        final EncodedKeySpec serverPubKey2Spec = new X509EncodedKeySpec(serverPubKeyBytes);
        final PublicKey serverPubKey2 = clientKeyFactory.generatePublic(serverPubKey2Spec);
        logger.info("server PublicKey returned to client:" + HexFormat.of().formatHex(serverPubKey2.getEncoded()));
        final KeyAgreement clientKeyAgreement = KeyAgreement.getInstance("ECDH");
        clientKeyAgreement.init(clientPriKey);
        clientKeyAgreement.doPhase(serverPubKey2, true);
        byte[] clientSecretKeyBytes = clientKeyAgreement.generateSecret();
        logger.info("SecretKey on client:" + HexFormat.of().formatHex(clientSecretKeyBytes));

        // summary
        final var bos = new ByteArrayOutputStream();
        bos.write(sessionId.getBytes());
        bos.write(randomNo.getBytes());
        bos.write(clientSecretKeyBytes);

        // create secretkey for AES256
        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        final byte[] keyMaterial = md.digest(bos.toByteArray());
        md.reset();
        final byte[] sharedSecretKeyBytes = Arrays.copyOfRange(keyMaterial, 0, 256 / 16);
        final byte[] ivBytes = Arrays.copyOfRange(keyMaterial, 256 / 16, 256 / 8);
        logger.info("SharedSecretKey len:" + sharedSecretKeyBytes.length);
        logger.info("ivBytes len:" + ivBytes.length);

        // AES256GCM
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final SecretKey sharedSecretKey = new SecretKeySpec(sharedSecretKeyBytes, "AES");
        final IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, sharedSecretKey, iv);

        // encrypt
        final var encryptedPasswd = cipher.doFinal(userPasswd.getBytes(StandardCharsets.UTF_8));
        logger.info("EncryptedPasswd:" + HexFormat.of().formatHex(encryptedPasswd));

        // decrypt
        cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey, iv);
        final var orgUserPasswd = cipher.doFinal(encryptedPasswd);

        logger.info("OrgUserPasswd:" + new String(orgUserPasswd, StandardCharsets.UTF_8));

    }
}
