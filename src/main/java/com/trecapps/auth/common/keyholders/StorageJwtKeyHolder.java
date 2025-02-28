package com.trecapps.auth.common.keyholders;

import com.trecapps.auth.web.services.IUserStorageService;

/**
 * Looks for Keys in the Storage Account of the User Service
 *
 * Note: NOT Recommended for Production apps, the other beans are preferred
 */
public class StorageJwtKeyHolder extends IJwtKeyHolder{

    IUserStorageService userStorageService;

    public StorageJwtKeyHolder(
            IUserStorageService userStorageService,
            String publicKeyStr,
            String privateKeyStr
    ){
        super(publicKeyStr, privateKeyStr);
        this.userStorageService = userStorageService;
    }

    public StorageJwtKeyHolder(
            IUserStorageService userStorageService,
            String publicKeyStr,
            String privateKeyStr,
            String publicKeyStrNotify,
            String privateKeyStrNotify
    ){
        super(publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify);
        this.userStorageService = userStorageService;
    }


    @Override
    protected String getKey(KeyPathHolder holder, int ignore) {
        if(!holder.isKeySet())
        {
            holder.setKey(userStorageService.retrieveKey(holder.getKeyPath()));
        }
        return holder.getKey();
    }
}
