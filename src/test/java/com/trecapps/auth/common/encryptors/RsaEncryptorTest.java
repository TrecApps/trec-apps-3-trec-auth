package com.trecapps.auth.common.encryptors;

import com.trecapps.auth.EncryptableTestObj;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IEncryptorKeyHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class RsaEncryptorTest {

    @Mock
    IEncryptorKeyHolder keyHolder;

    IFieldEncryptor rsaFieldEncryptor;

    static String noEncrypt = "Not Encrypted";
    static String doEncrypt = "I may be Encrypted when you read this!";

    String publicKeyPath = "rsaPublicKey";
    String privateKeyPath = "rsaPrivateKey";



    @BeforeEach
    void prepare()
    {
        Mockito.doReturn(RSATestHelper.publicKeyValue).when(keyHolder).getSecret(publicKeyPath);
        Mockito.doReturn(RSATestHelper.privateKeyValue).when(keyHolder).getSecret(privateKeyPath);

        rsaFieldEncryptor = new RsaFieldEncryptor(keyHolder, publicKeyPath, privateKeyPath);
    }

    @Test
    void testRsa()
    {
        EncryptableTestObj obj = new EncryptableTestObj();

        obj.getListOfStrings().add("String 1");
        obj.getListOfStrings().add("String 2");

        obj.getSetOfStrings().add("String 1");
        obj.getSetOfStrings().add("String 2");

        obj.setEncryptedField(doEncrypt);
        obj.setBasicField(noEncrypt);

        obj = rsaFieldEncryptor.encrypt(obj);

        Assertions.assertTrue(rsaFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        Assertions.assertTrue(rsaFieldEncryptor.isFieldEncrypted(obj.getListOfStrings().get(0)));
        String field = obj.getSetOfStrings().toArray(new String[0])[1];
        Assertions.assertTrue(rsaFieldEncryptor.isFieldEncrypted(field));

        Assertions.assertNotEquals(doEncrypt, obj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, obj.getBasicField());

        obj = rsaFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        obj = rsaFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getBasicField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getListOfStrings().get(0)));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getSetOfStrings().toArray(new String[0])[1]));

        Assertions.assertEquals(doEncrypt, obj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, obj.getBasicField());
    }

    @Test
    void testRsaNull()
    {
        EncryptableTestObj obj = new EncryptableTestObj();

        obj = rsaFieldEncryptor.encrypt(obj);

        Assertions.assertNull(obj.getBasicField());
        Assertions.assertNull(obj.getEncryptedField());
    }

    @Test
    void testRsaChildObject()
    {
        EncryptableTestObj obj = new EncryptableTestObj();

        EncryptableTestObj objChildObj = new EncryptableTestObj();
        objChildObj.setBasicField(noEncrypt);
        objChildObj.setEncryptedField(doEncrypt);
        obj.setChildObject(objChildObj);

        obj = rsaFieldEncryptor.encrypt(obj);
        objChildObj = obj.getChildObject();

        Assertions.assertTrue(rsaFieldEncryptor.isFieldEncrypted(objChildObj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(objChildObj.getBasicField()));

        Assertions.assertNotEquals(doEncrypt, objChildObj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, objChildObj.getBasicField());

        obj = rsaFieldEncryptor.decrypt(obj);
        objChildObj = obj.getChildObject();

        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(objChildObj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(objChildObj.getBasicField()));

        Assertions.assertEquals(doEncrypt, objChildObj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, objChildObj.getBasicField());
    }
}
