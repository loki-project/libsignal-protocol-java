package org.whispersystems.libsignal.loki;

import org.whispersystems.curve25519.Curve25519;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class DiffieHellman {
    private static Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);
    private static int ivLength = 16;
    private static String algorithm = "AES/CBC/PKCS5Padding";

    public static byte[] encrypt(byte[] plainTextData, byte[] symmetricKey)
        throws GeneralSecurityException
    {
        byte[] iv = getSecretBytes(ivLength);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encryptedMessage = cipher.doFinal(plainTextData);
        return concat(iv, encryptedMessage);
    }

    public static byte[] encrypt(byte[] plainTextData, byte[] publicKey, byte[] privateKey)
        throws GeneralSecurityException
    {
        return encrypt(plainTextData, curve.calculateAgreement(publicKey, privateKey));
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] symmetricKey)
            throws GeneralSecurityException
    {
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, ivLength);
        byte[] body = Arrays.copyOfRange(encryptedData, ivLength, encryptedData.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(body);
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] publicKey, byte[] privateKey)
        throws GeneralSecurityException
    {
        return decrypt(encryptedData, curve.calculateAgreement(publicKey, privateKey));
    }

    private static byte[] getSecretBytes(int size) throws NoSuchAlgorithmException {
        byte[] secret = new byte[size];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(secret);
        return secret;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}

