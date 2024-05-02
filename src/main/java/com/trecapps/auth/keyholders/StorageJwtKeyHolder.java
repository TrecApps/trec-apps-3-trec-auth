package com.trecapps.auth.keyholders;


import com.trecapps.auth.services.core.IUserStorageService;

/**
 * Looks for Keys in the Storage Account of the User Service
 *
 * Note: NOT Recommended for Production apps, the other beans are preferred
 */
public class StorageJwtKeyHolder implements IJwtKeyHolder{

    String publicKey;
    String privateKey;

    public StorageJwtKeyHolder(
            IUserStorageService userStorageService,
            String publicKeyStr,
            String privateKeyStr
    ){
        this.publicKey = userStorageService.retrieveKey(publicKeyStr);
        this.privateKey = userStorageService.retrieveKey(privateKeyStr);
    }

    @Override
    public String getPublicKey() {
        return publicKey;
    }

    @Override
    public String getPrivateKey() {
        return privateKey;
    }
}
