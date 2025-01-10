package com.trecapps.auth.common.keyholders;

import com.trecapps.auth.common.models.RsaKeyPair;
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
    public String getPublicKey(int version) {
        basicPublic.setKey(null);
        return getPublicKey(RsaKeyPair.BASIC_AUTH, version);
    }
    public String getPrivateKey() {
        return getPrivateKey(RsaKeyPair.BASIC_AUTH);
    }
    public String getPrivateKey(int version) {
        basicPrivate.setKey(null);
        return getPrivateKey(RsaKeyPair.BASIC_AUTH, version);
    }

    /**
     * Retrieves the key according to the specified means of doing so
     *
     * @param holder holds the name of the key
     * @param version the version to retrieve (0 means latest)
     */
    protected abstract String getKey(KeyPathHolder holder, int version);

    public String getPublicKey(RsaKeyPair pair){
        return getPublicKey(pair, 0);
    }

    public String getPublicKey(RsaKeyPair pair, int version){
        KeyPathHolder holder = pair.equals(RsaKeyPair.BASIC_AUTH) ? basicPublic : notifyPublic;

        return getKey(holder, version);
    }

    public String getPrivateKey(RsaKeyPair pair){
        return getPrivateKey(pair, 0);
    }

    public String getPrivateKey(RsaKeyPair pair, int version){
        KeyPathHolder holder = pair.equals(RsaKeyPair.BASIC_AUTH) ? basicPrivate : notifyPrivate;

        return getKey(holder, version);
    }

    public void updateKey(String publicKey, String privateKey){

    }
}
