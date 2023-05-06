package org.harryng.demo.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

public class SecurityUtil {
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);
    private static Map<String, MessageDigest> messageDigestMap = null;

    static {
        messageDigestMap = new HashMap<>();
        String[] msgDigestNames = {"MD5", "SHA1", "SHA-256", "SHA-512"};
        Stream.of(msgDigestNames).forEach(e -> {
            try {
                MessageDigest md = MessageDigest.getInstance(e);
                messageDigestMap.put(e, md);
            } catch (NoSuchAlgorithmException ex) {
                logger.error("", e);
            }
        });
    }

    public static MessageDigest getMessageDigest(String name) {
        return messageDigestMap.get(name);
    }

    public static byte[] hashMessage(String mdAlg, byte[] msgBin) {
        byte[] result = {};
        result = getMessageDigest(mdAlg).digest(msgBin);
        return result;
    }
}
