package com.trecapps.auth.common.encryptors;

import com.trecapps.auth.common.keyholders.IEncryptorKeyHolder;
import lombok.SneakyThrows;
import org.springframework.jdbc.support.KeyHolder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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

    // Use this as a fallback for old fields encrypted under AES BCB
    Cipher aesCbcCipherDecrypt;

    SecretKey key;

    // Use these for new AES GCM encryption
//    Cipher aesCipherEncrypt;
//    Cipher aesCipherDecrypt;

    @SneakyThrows
    AesFieldEncryptor(
            IEncryptorKeyHolder keyHolder,
            String aesPassword,
            String aesSalt,
            String aesIvCbcBytes)
    {
        String ivBytesCbcStr = keyHolder.getSecret(aesIvCbcBytes);

//        String[] bytesStr = ivBytesStr.split(",");
//        byte[] ivBytes = new byte[bytesStr.length];
//        for (int c = 0; c < bytesStr.length; c++) {
//            ivBytes[c] = Byte.parseByte(bytesStr[c]);
//        }
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivBytes);

        String[] bytesStr = ivBytesCbcStr.split(",");
        byte[] ivBytes = new byte[bytesStr.length];
        for (int c = 0; c < bytesStr.length; c++) {
            ivBytes[c] = Byte.parseByte(bytesStr[c]);
        }
        IvParameterSpec ivspec = new IvParameterSpec(ivBytes);
        String password = keyHolder.getSecret(aesPassword);
        String salt = keyHolder.getSecret(aesSalt);

        key = getKeyFromPassword(password, salt);

        // Set up CBC Decryption for backwards compatibility
        aesCbcCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        aesCbcCipherDecrypt.init(Cipher.DECRYPT_MODE, key, ivspec);

        // Set up GCM Encryption and Decryption for new mode
        // Set the GCM parameters


//        aesCipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
//        aesCipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
//        aesCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
//        aesCipherDecrypt.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
    }

    @SneakyThrows
    Cipher getDecryptionCipher(byte[] iv) {
        Cipher aesCipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipherDecrypt.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return aesCipherDecrypt;
    }

    @SneakyThrows
    Cipher getEncryptionCipher() {
        Cipher aesCipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        return aesCipherEncrypt;
    }

    @SneakyThrows
    private String encryptField(String value){
        if(isFieldEncrypted(value)) return value;
        Cipher encryptor = getEncryptionCipher();
        byte[] result = encryptor.doFinal(value.getBytes(StandardCharsets.UTF_8));

        return wrapField(String.format("%s:%s",Base64.getEncoder().encodeToString(result), Base64.getEncoder().encodeToString(encryptor.getIV())));
    }

    @SneakyThrows
    private String decryptField(String value){

        while(isFieldEncrypted(value)){
            value = unwrapField(value);

            // Determine if using CBC or GCM
            String[] values = value.split(":");


            byte[] encryptedBytes = Base64.getDecoder().decode(values[0]);
            if(values.length == 1) {
                // Decrypted using old CBC
                byte[] decryptedBytes = aesCbcCipherDecrypt.doFinal(encryptedBytes);
                value = new String(decryptedBytes, StandardCharsets.UTF_8);
            } else {
                // Decrypted using new GCM
                byte[] storedIV = Base64.getDecoder().decode(values[1]);
                Cipher decryptor = getDecryptionCipher(storedIV);
                byte[] decryptedBytes = decryptor.doFinal(encryptedBytes);
                value = new String(decryptedBytes, StandardCharsets.UTF_8);
            }
        }

        return value;
    }

    @Override
    public <A> A encrypt(A obj) {
        if(obj == null) return null;

        if(obj instanceof String strObj)
            return (A) encryptField(strObj);


        Class objClass = obj.getClass();
        Field[] fields = obj.getClass().getDeclaredFields();

        List<EncryptableFields> fieldsList = getEncryptableFields(fields);



        fieldsList.forEach((EncryptableFields encField) -> {
            Field field = null;
            try {
                field = objClass.getDeclaredField(encField.field);

                field.setAccessible(true);

                Object fieldValue = field.get(obj);

                if(fieldValue instanceof String)
                    field.set(obj, encryptField(fieldValue.toString()));
                else if(fieldValue instanceof List collectionValue){
                    for(int c = 0; c < collectionValue.size(); c++)
                    {
                        collectionValue.set(c, encrypt(collectionValue.get(c)));
                    }
                }else if(fieldValue instanceof Set collectionValue){

                    field.set(obj, collectionValue.stream().map(this::encrypt).collect(Collectors.toSet()));
                }
                else if(fieldValue != null)
                    field.set(obj, encrypt(fieldValue));
            } catch (NoSuchFieldException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }

        });

        return obj;
    }

    @Override
    public <A> A decrypt(A obj) {
        if(obj == null) return null;

        if(obj instanceof String strObj)
            return (A) decryptField(strObj);

        Class objClass = obj.getClass();
        List<EncryptableFields> fieldsList = getEncryptableFields(objClass.getDeclaredFields());


        fieldsList.forEach((EncryptableFields encField) -> {
            Field field = null;
            try {
                field = objClass.getDeclaredField(encField.field);

                field.setAccessible(true);
                Object fieldValue = field.get(obj);

                if(fieldValue instanceof String) {
                    String decryptedValue = decryptField(fieldValue.toString());
                    field.set(obj, decryptedValue);
                }else if(fieldValue instanceof List collectionValue){
                    for(int c = 0; c < collectionValue.size(); c++)
                    {
                        collectionValue.set(c, decrypt(collectionValue.get(c)));
                    }
                }else if(fieldValue instanceof Set collectionValue){

                    field.set(obj, collectionValue.stream().map(this::decrypt).collect(Collectors.toSet()));
                }
                else if(fieldValue != null)
                    field.set(obj, decrypt(fieldValue));
            } catch (NoSuchFieldException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }

        });

        return obj;
    }
}
