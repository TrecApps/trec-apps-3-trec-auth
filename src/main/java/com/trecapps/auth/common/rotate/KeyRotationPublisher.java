package com.trecapps.auth.common.rotate;

import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.RsaKeyPair;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class KeyRotationPublisher implements Job {

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

        String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        StringBuilder pkBuilder = new StringBuilder();
        for(int i = 0; i < privateKeyStr.length(); i+=65){
            if(!pkBuilder.isEmpty())
                pkBuilder.append("|");

            int end = Math.min(i + 65, privateKeyStr.length());


            pkBuilder.append(privateKeyStr, i, end);
        }

        privateKeyStr = "-----BEGIN PRIVATE KEY-----|" + pkBuilder + "|-----END PRIVATE KEY-----";
        jwtKeyHolder.updateKey(publicKeyStr, privateKeyStr);
    }

    @Override
    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {
        run();
    }
}
