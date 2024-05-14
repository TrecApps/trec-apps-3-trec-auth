package com.trecapps.auth.common.encryptors;

import com.trecapps.auth.EncryptableTestObj;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.encryptors.RsaFieldEncryptor;
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

    // Note: These are test keys - DO NOT USE THEM IN THE ACTUAL APPLICATION!
    String publicKeyValue =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMvViSSRUt6x+wFN374WI2b3MguIk+" +
                    "MuSTSnq1f9I3sZulGEiOXffaFiKlecuewcPGbzdr1HecWdIGQVlfuRY61WzpR0XOAn" +
                    "XKycCBt0Nuuilfn6EtEGKyaobZ8W4k7OnVC0ZwhLiCTwj/nsVp7dptksXsiO3rduSm" +
                    "nnC+rTV7jnCczo6ESKcZazOvK0CrB8ZYIw/0grGcDKlOLyEJCxqRUTdfgKJb16O6pu" +
                    "dxrufsqktfJL9kZhHb4ggjFYnXXf+bt1Y7/H7gDKRVX1G6tNEVWdxAmov2MBq2jgIx" +
                    "KLnZbo9viLjqHqZHJ0t3+0K8/iFwyJPySan+1bo8CQI3FIJQIDAQAB";
    String privateKeyValue = 
            "-----BEGIN PRIVATE KEY-----|"+
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAy9WJJJFS3rH7|"+
                    "AU3fvhYjZvcyC4iT4y5JNKerV/0jexm6UYSI5d99oWIqV5y57Bw8ZvN2vUd5xZ0g|"+
                    "ZBWV+5FjrVbOlHRc4CdcrJwIG3Q266KV+foS0QYrJqhtnxbiTs6dULRnCEuIJPCP|"+
                    "+exWnt2m2SxeyI7et25KaecL6tNXuOcJzOjoRIpxlrM68rQKsHxlgjD/SCsZwMqU|"+
                    "4vIQkLGpFRN1+AolvXo7qm53Gu5+yqS18kv2RmEdviCCMViddd/5u3Vjv8fuAMpF|"+
                    "VfUbq00RVZ3ECai/YwGraOAjEoudluj2+IuOoepkcnS3f7Qrz+IXDIk/JJqf7Vuj|"+
                    "wJAjcUglAgMBAAECggEAHN3IHI8VlS9Tva3Nz5zB6s4NX/hbHC1tLjfMjPqRI8FY|"+
                    "Mk3nRqoIYuKJdKaGiE3iUmbluBcR/xkH9CQYGUs/0wlOkIKow4kqS5VqjUozBdAV|"+
                    "GViCyVNzlX1lxXgG8J51EBfX0v9qc7l4LU5xxOxnaoZkvtJPlegoAstFdULVHvKE|"+
                    "/b7jrTbpprXGudyPOqmR5Mi8tvUR1jPaMV0JfAuAqIEKQC0zAQ1QxxtAUWaoLYf/|"+
                    "ueCpR3XpDCC1X5YGmSzqYn52dSfCJ5yU7+32dfWK/RQuF83uxWsFL1Zf7CyyadqX|"+
                    "OWzEK8gwrnIIwx+Q+8Rtf4JDfh83CT9BWxAzGGfuYQKBgQD2jc2p3reHL6ZNJhq6|"+
                    "TibhtOXl4olu1fS59jSH+d5Tdce9n992MOnBTLRmhjdyXI9enQWYVI9qF3UOLGLR|"+
                    "GjEJeRNQ0b6lpQDVc0AYq/3XyQDmo/IbD8HnMq9/7O7/I61rhhgMHHm10UIVWDnZ|"+
                    "hlFmuSb/blF8RHWYZNv6TTEn9QKBgQDILsa2iTqZvJlkneihj/TUTHAPKta+KYiP|"+
                    "2eJ6tJAK2Gb5bD2RU+1BTbdXONSFTJUrnr0pwqJhYEX64umk7E205u4q3icwn+I2|"+
                    "oVp6fIoYeu0tDH+VAgmTJpgG7twxSxGgS6/kJhxZSrvTqRi+PVyIcGnCGykNXHbz|"+
                    "g++7+f3xcQKBgFouJdKDPve4awh+7nnEih42T3yVLpWWtouqTS6LK1G1m9h0+IQ/|"+
                    "gdCNINL7Np6i0mHV5yz/iPFSISONApvfC56eZX1DKotl3fc0z3X2usNJpwW1Y6GY|"+
                    "UuEgveZ5oDU8NHtGsdcEN1RUdOpfudEhevaqtGPrUuy0EZsrEPbtcxRdAoGBAKVt|"+
                    "unu4ljvcFuuGb2useohDDswJ++K0kg1G4xnCQ9MimJ6A67RApi20WtHyvfXWnuOo|"+
                    "T+zF0skj9VDq2miXe3QG70VvxvUw+5Fn8EyOxNSMKZpz3K84Os9nMnVwSXlW7x8H|"+
                    "zTh+oijMUMIO2MrGDMUYGN328gr/obGGE8TFSC2RAoGBAOt2KFWLbqAeBcwq6oqS|"+
                    "Mdqa8v99AugVHPNdMBzOzDHu+8rGZDiWMNfBD2GjngxmY3WTmGnyD5zZpNXJ3RSC|"+
                    "w0J4IUsUn1VUFyVBKn8O6ydcf/Fnm59lhVKXLi2qK1uxvh+dAvhhlFtf1Ao7j2GM|"+
                    "d2GAJvyhVv0PrFN4mIpH3vei|"
                    +"-----END PRIVATE KEY-----|";

    @BeforeEach
    void prepare()
    {
        Mockito.doReturn(publicKeyValue).when(keyHolder).getSecret(publicKeyPath);
        Mockito.doReturn(privateKeyValue).when(keyHolder).getSecret(privateKeyPath);

        rsaFieldEncryptor = new RsaFieldEncryptor(keyHolder, publicKeyPath, privateKeyPath);
    }

    @Test
    void testRsa()
    {
        EncryptableTestObj obj = new EncryptableTestObj();



        obj.setEncryptedField(doEncrypt);
        obj.setBasicField(noEncrypt);

        obj = rsaFieldEncryptor.encrypt(obj);

        Assertions.assertTrue(rsaFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        Assertions.assertNotEquals(doEncrypt, obj.getEncryptedField());
        Assertions.assertEquals(noEncrypt, obj.getBasicField());

        obj = rsaFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

        obj = rsaFieldEncryptor.decrypt(obj);

        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getEncryptedField()));
        Assertions.assertFalse(rsaFieldEncryptor.isFieldEncrypted(obj.getBasicField()));

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
