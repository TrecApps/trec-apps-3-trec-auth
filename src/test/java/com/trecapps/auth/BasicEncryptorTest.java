package com.trecapps.auth;

import com.trecapps.auth.encryptors.BasicFieldEncryptor;
import com.trecapps.auth.encryptors.EncryptableFields;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;

@ExtendWith(MockitoExtension.class)
public class BasicEncryptorTest {

    @Test
    void testBasicEncrypt(){
        BasicFieldEncryptor encryptor = new BasicFieldEncryptor();

        String nonEncrypt = "Don't Encrypt Me";
        String doEncrypt = "Encrypt Me";
        EncryptableTestObj obj = new EncryptableTestObj();
        obj.setBasicField(nonEncrypt);
        obj.setEncryptedField(doEncrypt);

        obj = encryptor.encrypt(obj);

        Assertions.assertEquals(nonEncrypt, obj.getBasicField());
        Assertions.assertEquals(doEncrypt, obj.getEncryptedField());

        obj = encryptor.decrypt(obj);
        Assertions.assertEquals(nonEncrypt, obj.getBasicField());
        Assertions.assertEquals(doEncrypt, obj.getEncryptedField());
    }

    @Test
    void testDefaultMethods(){
        BasicFieldEncryptor encryptor = new BasicFieldEncryptor();

        String plainText = "This is plain text";
        String encText = "_ENC_(This is plain text)";

        String res = encryptor.wrapField(plainText);

        Assertions.assertEquals(encText, res);
        Assertions.assertTrue(encryptor.isFieldEncrypted(res));

        res = encryptor.unwrapField(res);

        Assertions.assertEquals(plainText, res);
        Assertions.assertFalse(encryptor.isFieldEncrypted(res));

        res = encryptor.unwrapField(plainText);

        Assertions.assertEquals(plainText, res);
        Assertions.assertFalse(encryptor.isFieldEncrypted(res));
    }

    @Test
    void testGetEncryptableFieldList()
    {
        BasicFieldEncryptor encryptor = new BasicFieldEncryptor();

        String nonEncrypt = "Don't Encrypt Me";
        String doEncrypt = "Encrypt Me";
        EncryptableTestObj obj = new EncryptableTestObj();
        obj.setBasicField(nonEncrypt);
        obj.setEncryptedField(doEncrypt);


        Field[] fields = obj.getClass().getDeclaredFields();


        List<EncryptableFields> encFields = encryptor.getEncryptableFields(fields);

        Assertions.assertEquals(1, encFields.size());
        Assertions.assertEquals("encryptedField", encFields.get(0).getField());
    }
}
