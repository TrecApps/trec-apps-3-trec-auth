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

@ExtendWith(MockitoExtension.class)
public class AesEncryptorTest {

    @Mock
    IEncryptorKeyHolder keyHolder;

    IFieldEncryptor aesFieldEncryptor;

    String aesPassword = "nuictyqo348cyt9834yx";
    String aesSalt = "nicouqyn58tx894ur";
    String ivBytes = "1,0,0,1,0,1,1,1,0,1,1,0,0,0,0,1";

    String keyPassword = "aesPassword";
    String keySalt = "aesSalt";
    String keyIvBytes = "ivBytes";


    static String noEncrypt = "Not Encrypted";
    static String doEncrypt = "I may be Encrypted when you read this!";

    @BeforeEach
    void prepare(){
        Mockito.doReturn(aesPassword).when(keyHolder).getSecret(keyPassword);
        Mockito.doReturn(aesSalt).when(keyHolder).getSecret(keySalt);
        Mockito.doReturn(ivBytes).when(keyHolder).getSecret(keyIvBytes);

        aesFieldEncryptor = new AesFieldEncryptor(keyHolder, keyPassword, keySalt, keyIvBytes);
    }

    @Test
    void testAes()
    {
        EncryptableTestObj obj = new EncryptableTestObj();



        obj.setEncryptedField(doEncrypt);
        obj.setBasicField(noEncrypt);

        obj = aesFieldEncryptor.encrypt(obj);

        Assertions.assertTrue(aesFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        Assertions.assertNotEquals(doEncrypt, obj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, obj.getBasicField());

        obj = aesFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        obj = aesFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(aesFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

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
