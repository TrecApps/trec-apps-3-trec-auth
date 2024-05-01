package com.trecapps.auth.keyholders;

import org.springframework.stereotype.Service;

/**
 * Retrieves the RSA Keys Used for JWT Authentication
 */
@Service
public interface IJwtKeyHolder {

    String getPublicKey();
    String getPrivateKey();

}
