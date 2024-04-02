package com.trecapps.auth.encryptors;

import com.trecapps.auth.keyholders.IEncryptorKeyHolder;
import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.List;

/**
 * Encrypts and decrypts marked fields of the specified object using the AES Algorithm
 *
 * Params:
 *  aesPassword - name of the password used to generate the AES Key
 *  aesSalt - name of the salt used to generate the AES Key
 *  aesIvBytes - name of the value used to generate the ivBytes (the value should be in the form of "x,y,z,..."
 *      where each value can be cast into a signed byte, such that an IvParameterSpec can be generated)
 */
public class AesFieldEncryptor implements IFieldEncryptor{

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
    }

    Cipher aesCipherEncrypt;
    Cipher aesCipherDecrypt;

    @SneakyThrows
    AesFieldEncryptor(
            IEncryptorKeyHolder keyHolder,
            String aesPassword,
            String aesSalt,
            String aesIvBytes)
    {
        String[] bytesStr = aesIvBytes.split(",");
        byte[] ivBytes = new byte[bytesStr.length];
        for (int c = 0; c < bytesStr.length; c++) {
            ivBytes[c] = Byte.parseByte(bytesStr[c]);
        }
        IvParameterSpec ivspec = new IvParameterSpec(ivBytes);
        String password = keyHolder.getSecret(aesPassword);
        String salt = keyHolder.getSecret(aesSalt);

        SecretKey key = getKeyFromPassword(password, salt);

        aesCipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        aesCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        aesCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, ivspec);
        aesCipherDecrypt.init(Cipher.DECRYPT_MODE, key, ivspec);
    }

    @SneakyThrows
    private String encryptField(String value){
        byte[] result = aesCipherEncrypt.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(result);
    }

    @SneakyThrows
    private String decryptField(String value){
        byte[] encryptedBytes = Base64.getDecoder().decode(value);
        byte[] decryptedBytes = aesCipherDecrypt.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    @Override
    public <A> A encrypt(A obj) {
        List<EncryptableFields> fieldsList = getEncryptableFields(obj.getClass().getFields());

        Class objClass = obj.getClass();

        fieldsList.forEach((EncryptableFields encField) -> {
            Field field = null;
            try {
                field = objClass.getDeclaredField(encField.field);

                field.setAccessible(true);
                field.set(obj, encryptField(field.get(obj).toString()));
            } catch (NoSuchFieldException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }

        });

        return obj;
    }

    @Override
    public <A> A decrypt(A obj) {
        List<EncryptableFields> fieldsList = getEncryptableFields(obj.getClass().getFields());

        Class objClass = obj.getClass();

        fieldsList.forEach((EncryptableFields encField) -> {
            Field field = null;
            try {
                field = objClass.getDeclaredField(encField.field);

                field.setAccessible(true);
                field.set(obj, decryptField(field.get(obj).toString()));
            } catch (NoSuchFieldException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }

        });

        return obj;
    }
}
