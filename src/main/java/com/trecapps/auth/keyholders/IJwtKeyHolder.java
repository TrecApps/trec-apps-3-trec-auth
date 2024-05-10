package com.trecapps.auth.keyholders;

import com.trecapps.auth.services.core.RsaKeyPair;
import org.springframework.stereotype.Service;

/**
 * Retrieves the RSA Keys Used for JWT Authentication
 */
@Service
public abstract class IJwtKeyHolder {

    KeyPathHolder basicPublic = new KeyPathHolder();
    KeyPathHolder basicPrivate = new KeyPathHolder();

    KeyPathHolder notifyPublic = new KeyPathHolder();
    KeyPathHolder notifyPrivate = new KeyPathHolder();

    protected IJwtKeyHolder(String publicKeyStr,
            String privateKeyStr ){
        this.basicPublic.setKeyPath(publicKeyStr);
        this.basicPrivate.setKeyPath(privateKeyStr);
    }

    protected IJwtKeyHolder(String publicKeyStrBasic,
                            String privateKeyStrBasic,
                            String publicKeyStrNotify,
                            String privateKeyStrNotify){
        this.basicPublic.setKeyPath(publicKeyStrBasic);
        this.basicPrivate.setKeyPath(privateKeyStrBasic);

        this.notifyPublic.setKeyPath(publicKeyStrNotify);
        this.notifyPrivate.setKeyPath(privateKeyStrNotify);
    }

    public String getPublicKey(){
        return getPublicKey(RsaKeyPair.BASIC_AUTH);
    }
    public String getPrivateKey() {
        return getPrivateKey(RsaKeyPair.BASIC_AUTH);
    }

    protected abstract String getKey(KeyPathHolder holder);

    String getPublicKey(RsaKeyPair pair){
        KeyPathHolder holder = pair.equals(RsaKeyPair.BASIC_AUTH) ? basicPublic : notifyPublic;

        return getKey(holder);
    }
    String getPrivateKey(RsaKeyPair pair){
        KeyPathHolder holder = pair.equals(RsaKeyPair.BASIC_AUTH) ? basicPrivate : notifyPrivate;

        return getKey(holder);
    }
}
