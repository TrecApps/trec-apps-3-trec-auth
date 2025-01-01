package com.trecapps.auth.common.models;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import lombok.SneakyThrows;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class JwtKeyArray {

    @Data
    public static class DecodedHolder {
        Optional<DecodedJWT> decodedJwt = Optional.empty();
        boolean keyOutdated = false; // If a previous key set was used to generate the decoded JWT, set this to true
    }

    public record JwtKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        public JwtKeyPair {
            Objects.requireNonNull(publicKey);
            Objects.requireNonNull(privateKey);
        }
    }

    public JwtKeyArray(int maxSize) {
        this.keys = new AtomicReference<>(new LimitList<>(maxSize));
    }

    AtomicReference<LimitList<JwtKeyPair>> keys;

    @SneakyThrows
    public void AddKey(String publicKeyStr, String privateKeyStr) {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr));
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);

        try (PEMParser parser = new PEMParser(new StringReader(privateKeyStr))) {

            PemObject pemObject = parser.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            RSAPrivateKey privateKey =  (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);

            LimitList<JwtKeyPair> tempKeys = new LimitList<>(keys.get());

            tempKeys.add(new JwtKeyPair(publicKey, privateKey));
            keys.set(tempKeys);

        }
    }

    public DecodedHolder decodeJwt(String token){
        DecodedHolder ret = new DecodedHolder();

        LinkedList<JwtKeyPair> tempKeys = new LimitList<>(keys.get());
        Collections.reverse(tempKeys);


        while(!tempKeys.isEmpty()){
            JwtKeyPair curPair = tempKeys.removeFirst();
            try{
                DecodedJWT decodedJWT = JWT.require(
                        Algorithm.RSA512(
                                curPair.publicKey(),
                                curPair.privateKey()))
                        .build()
                        .verify(token);
                ret.decodedJwt = Optional.of(decodedJWT);
                return ret;
            } catch(JWTVerificationException e) {
                ret.keyOutdated = true;
            }
        }



        return ret;
    }

    public String encodeJWT(JWTCreator.Builder jwtBuilder) {
        JwtKeyPair lastPair = keys.get().peekLast();
        return jwtBuilder.sign(Algorithm.RSA512(Objects.requireNonNull(lastPair).publicKey(), lastPair.privateKey()));
    }


}
