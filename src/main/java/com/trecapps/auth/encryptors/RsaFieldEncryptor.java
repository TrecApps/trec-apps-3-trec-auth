package com.trecapps.auth.encryptors;

import com.azure.security.keyvault.secrets.SecretClient;
import com.trecapps.auth.keyholders.IEncryptorKeyHolder;
import lombok.SneakyThrows;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;

import javax.crypto.Cipher;
import java.io.StringReader;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class RsaFieldEncryptor implements IFieldEncryptor{

    static Class<EncryptedField> encryptedFieldClass = EncryptedField.class;

    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;

    Cipher rsaCipherEncrypt;
    Cipher rsaCipherDecrypt;

    Base64.Encoder encoder;
    Base64.Decoder decoder;

    @SneakyThrows
    RsaFieldEncryptor(IEncryptorKeyHolder keyHolder, String publicKeyPath, String privateKeyPath){
        String pubKeyStr = keyHolder.getSecret(publicKeyPath);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKeyStr));
        publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);

        String privKeyStr = keyHolder.getSecret(privateKeyPath);
        try (PEMParser parser = new PEMParser(new StringReader(privKeyStr))) {

            PemObject pemObject = parser.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);
        }

        rsaCipherEncrypt = Cipher.getInstance("RSA");
        rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey);

        rsaCipherDecrypt = Cipher.getInstance("RSA");
        rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, privateKey);

        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
    }

    @SneakyThrows
    private String EncryptField(String value){
        byte[] result = rsaCipherEncrypt.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return encoder.encodeToString(result);
    }

    @SneakyThrows
    private String decryptField(String value){
        byte[] encryptedBytes = decoder.decode(value);
        byte[] decryptedBytes = rsaCipherDecrypt.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    @Override
    public <A> A encrypt(A obj) {
        List<EncryptableFields> fieldsList = getEncryptableFields(obj.getClass().getFields());
        return null;
    }

    @Override
    public <A> A decrypt(A obj) {
        List<EncryptableFields> fieldsList = getEncryptableFields(obj.getClass().getFields());
        return null;
    }
}
