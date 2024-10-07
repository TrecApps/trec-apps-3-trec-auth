package com.trecapps.auth.common.encryptors;

import com.trecapps.auth.EncryptableTestObj;
import com.trecapps.auth.common.encryptors.AesFieldEncryptor;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.keyholders.IEncryptorKeyHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@ExtendWith(MockitoExtension.class)
public class AesEncryptorTest {

    @Mock
    IEncryptorKeyHolder keyHolder;

    IFieldEncryptor aesFieldEncryptor;

    String aesPassword = "nuictyqo348cyt9834yx";
    String aesSalt = "nicouqyn58tx894ur";
    String ivBytes = "1,0,0,1,0,1,1,1,0,1,1,0";
    String ivBytesCbc = "1,0,0,1,0,1,1,1,0,1,1,0,0,0,0,1";

    String keyPassword = "aesPassword";
    String keySalt = "aesSalt";
    String keyIvBytes = "ivBytes";
    String keyIvBytesCbc = "ivBytesCbc";


    static String noEncrypt = "Not Encrypted";
    static String doEncrypt = "I may be Encrypted when you read this!";

    @BeforeEach
    void prepare(){
        Mockito.doReturn(aesPassword).when(keyHolder).getSecret(keyPassword);
        Mockito.doReturn(aesSalt).when(keyHolder).getSecret(keySalt);
        //Mockito.doReturn(ivBytes).when(keyHolder).getSecret(keyIvBytes);
        Mockito.doReturn(ivBytesCbc).when(keyHolder).getSecret(keyIvBytesCbc);

        aesFieldEncryptor = new AesFieldEncryptor(keyHolder, keyPassword, keySalt, keyIvBytesCbc);
    }

    @Test
    void testCBCCompatabiity() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        // First set up am AES CBC encryptor
        String[] bytesStr = ivBytesCbc.split(",");
        byte[] ivBytes = new byte[bytesStr.length];
        for (int c = 0; c < bytesStr.length; c++) {
            ivBytes[c] = Byte.parseByte(bytesStr[c]);
        }
        IvParameterSpec ivspec = new IvParameterSpec(ivBytes);


        SecretKey key = AesFieldEncryptor.getKeyFromPassword(aesPassword, aesSalt);

        Cipher aesCbcCipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        aesCbcCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, ivspec);


        String plainText = "Unencrypted Plain Text (for AES CBC Encryption)";
        byte[] result = aesCbcCipherEncrypt.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        String FRONT_WRAP = "_ENC_(";
        String BACK_WRAP = ")";

        String encryptedField = String.format("%s%s%s", FRONT_WRAP, Base64.getEncoder().encodeToString(result), BACK_WRAP);

        Method decryptFieldMethod = AesFieldEncryptor.class.getDeclaredMethod("decryptField", String.class);
        decryptFieldMethod.setAccessible(true);


        String decryptedField = (String) decryptFieldMethod.invoke(aesFieldEncryptor, encryptedField);

        Assertions.assertEquals(plainText, decryptedField);
    }

    @Test
    void testAes()
    {
        EncryptableTestObj obj = new EncryptableTestObj();



        obj.setEncryptedField(doEncrypt);
        obj.setBasicField(noEncrypt);

        obj.getListOfStrings().add("String 1");
        obj.getListOfStrings().add("String 2");

        obj.getSetOfStrings().add("String 1");
        obj.getSetOfStrings().add("String 2");

        obj = aesFieldEncryptor.encrypt(obj);

        Assertions.assertTrue(aesFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        Assertions.assertTrue(aesFieldEncryptor.isFieldEncrypted(obj.getListOfStrings().get(0)));
        String field = obj.getSetOfStrings().toArray(new String[0])[1];
        Assertions.assertTrue(aesFieldEncryptor.isFieldEncrypted(field));

        Assertions.assertNotEquals(doEncrypt, obj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, obj.getBasicField());

        obj = aesFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        obj = aesFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getBasicField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getListOfStrings().get(0)));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getSetOfStrings().toArray(new String[0])[1]));

        Assertions.assertEquals(doEncrypt, obj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, obj.getBasicField());
    }

    @Test
    void testAesNull()
    {
        EncryptableTestObj obj = new EncryptableTestObj();

        obj = aesFieldEncryptor.encrypt(obj);

        Assertions.assertNull(obj.getBasicField());
        Assertions.assertNull(obj.getEncryptedField());
    }

    @Test
    void testAesChildObject()
    {
        EncryptableTestObj obj = new EncryptableTestObj();

        EncryptableTestObj objChildObj = new EncryptableTestObj();
        objChildObj.setBasicField(noEncrypt);
        objChildObj.setEncryptedField(doEncrypt);
        obj.setChildObject(objChildObj);

        obj = aesFieldEncryptor.encrypt(obj);
        objChildObj = obj.getChildObject();

        Assertions.assertTrue(aesFieldEncryptor.isFieldEncrypted(objChildObj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(objChildObj.getBasicField()));

        Assertions.assertNotEquals(doEncrypt, objChildObj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, objChildObj.getBasicField());

        obj = aesFieldEncryptor.decrypt(obj);
        objChildObj = obj.getChildObject();

        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(objChildObj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(objChildObj.getBasicField()));

        Assertions.assertEquals(doEncrypt, objChildObj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, objChildObj.getBasicField());
    }


}
