package com.trecapps.auth.models;

import lombok.Data;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
public class KeyPair {

    RSAPublicKey publicKey;

    RSAPrivateKey privateKey;
}
