package com.util.crypto;

import java.security.NoSuchAlgorithmException;

import static com.util.crypto.CryptoUtil.md5;
import static com.util.crypto.CryptoUtil.sha256;

/**
 * 키값: secret key
 * 문자열 "hello, world!" 문자열을 해시, 암/복호화해본다.
 */
public class CryptoMain {
    public static void main(String[] args) throws Exception {
        String plainText = "Hello, World!";
        String key = "secret key";

        System.out.println("MD5 : " + plainText + " - " + md5(plainText));
        System.out.println("SHA-256 : " + plainText + " - " + sha256(plainText));

        // AES256으로 암/복호화 수행
        String encrypted = CryptoUtil.encryptAES256("Hello, World!!", key);

        System.out.println("AES256 : enc - " + encrypted);
        System.out.println("AES256 : dec - " + CryptoUtil.decryptAES256(encrypted, key));

    }
}
