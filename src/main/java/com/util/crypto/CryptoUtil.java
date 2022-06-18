package com.util.crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * 목표: java.security 라이브러리를 사용해서 MD5, SHA-256으로 해시하는 방법과 AES-256으로 암호화/복호화를 한다.
 *
 * MD5, SHA-256은 단방향 암호화로 비밀번호를 암호화 하거나 데이터 전송 등에서 무결성을 체크하는데 사용한다.
 * MD5는 128bit로 서로 다른 값에 같은 해시가 발생하는 현상이 발견되었고, 빠르게 해시가 가능해서 비밀번호 만드는데는 안전하지 않음 -> SHA-256 사용을 권장하는 추세임
 *
 * 적절한 길이의 salt, bcrypt, scrypt, pbkdf2와 같은 느린 알고리즘을 적용해서 무작위 공격에 대비해야 안전한 비밀번호 생성이 가능
 */
public class CryptoUtil {

    /**
     * MD5 해시
     * - MessageDigest 객체 생성 시 알고리즘을 "MD5"로 함
     * - 해시된 데이터는 바이트 배열의 바이너리 데이터이므로 16진수 문자열로 변환함
     */
    public static String md5(String msg) throws NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(msg.getBytes());

        return byteToHexString(md5.digest());
    }

    /**
     * SHA-256 해시
     * - MessageDigest 객체 생성 시 알고리즘을 "SHA-256"로 함
     * - 해시된 데이터는 바이트 배열의 바이너리 데이터이므로 16진수 문자열로 변환함
     */
    public static String sha256(String msg) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(msg.getBytes());

        return byteToHexString(sha256.digest());
    }

    /**
     * 바이트 배열을 hex 문자열로 변환
     * @param byte[] digest
     */
    private static String byteToHexString(byte[] datas) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte data : datas) {
            stringBuilder.append(Integer.toString((data & 0xff) + 0x100, 16).substring(1));
        }

        return stringBuilder.toString();
    }

    /**
     * AES-256 으로 암호화
     * - AES256은 키가 256bit 즉, 32바이트 문자열이어야 한다.
     * - 여기서는 임의의 길이의 key문자열에 랜덤 salt를 첨가 후 해시해서 256bit 키를 생성
     * - 암호화 모드: CBC, 길이를 일정하게 하기 위해 PKCS5 패딩 사용
     * - 결과값에 salt, iv 값을 추가해서 Base64로 인코딩해서 반환
     * (java8에는 Base64 기능이 포함되어 있지만, 그 이하 버전인 경우 apache common codec 라이브러리 등을 사용해서 Base64 인코딩 기능 사용 가능
     */
    public static String encryptAES256(String msg, String key) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        byte[] saltBytes = bytes;

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        // 70000번 해시 후 256bit 길이의 키를 만든다.
        PBEKeySpec pbeKeySpec = new PBEKeySpec(key.toCharArray(), saltBytes, 70000, 256);

        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // 알고리즘/모드/패딩
        // CBC : Cipher Block Chaining Mode
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters parameters = cipher.getParameters();

        // Initial Vector (1단계 암호화 블록용)
        byte[] ivBytes = parameters.getParameterSpec(IvParameterSpec.class).getIV();

        byte[] encryptedCipherBytes = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));

        byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedCipherBytes.length];

        System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
//        System.out.println("buffer = " + buffer);

        System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
//        System.out.println("buffer = " + buffer);

        System.arraycopy(encryptedCipherBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedCipherBytes.length);
//        System.out.println("buffer = " + buffer);

        // base64 로 인코딩해서 반환
        /**
         * * Base64란? 8비트 이진 데이터(ex. 실행파일, zip파일, ..)를 문자 코드에 영향 받지 않는 공통 ASCII 영역의 문자들로만 이루어진 일련의 문자열로 바꾸는 인코딩 방식.
         * -> 원본 문자열 > ASCII binary > 6bit 단위 cut > base64 encoding..
         * -> 이미지나 오디오 등 binary data 전송 시 동일 전송 데이터를 보장하기 위함...
         */
        return Base64.getEncoder().encodeToString(buffer);
    }

    /**
     * 암호화된 내용을 복호화
     * - 앞에서 암호화된 내용을 Base64 디코드한다.
     * - 붙혔던 salt, iv를 제거
     * - 복호화를 수행하고 복호화된 바이트 배열을 문자열로 반환한다.
     */
    public static String decryptAES256(String msg, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(msg));

        byte[] saltBytes = new byte[20];
        buffer.get(saltBytes, 0, saltBytes.length);

        byte[] ivBytes = new byte[cipher.getBlockSize()];
        buffer.get(ivBytes, 0, ivBytes.length);

        byte[] encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes.length];
        buffer.get(encryptedTextBytes);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), saltBytes, 70000, 256);

        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return new String(decryptedTextBytes);
    }
}
