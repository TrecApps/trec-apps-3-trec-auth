package com.trecapps.auth.common.rotate;

import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.RsaKeyPair;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyRotationPublisher {

    @Autowired
    IJwtKeyHolder jwtKeyHolder;

    KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");

    public KeyRotationPublisher() throws NoSuchAlgorithmException {

        factory.initialize(4096, SecureRandom.getInstanceStrong());
    }

    public void run(){
        KeyPair keyPair = factory.generateKeyPair();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        String privateKeyStr = new String(privateKey.getEncoded());
        String publicKeyStr = new String(publicKey.getEncoded());

        // To-Do: Format Keys to fit


        // End To-Do
        jwtKeyHolder.updateKey(publicKeyStr, privateKeyStr);
    }

}
