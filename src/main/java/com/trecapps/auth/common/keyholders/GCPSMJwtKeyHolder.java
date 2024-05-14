package com.trecapps.auth.common.keyholders;

import lombok.SneakyThrows;

public class GCPSMJwtKeyHolder extends IJwtKeyHolder{

    GCPSMEncryptorKeyHolder gcpKeyHolder;

    @SneakyThrows
    GCPSMJwtKeyHolder(
            String projectId,
            String publicKeyPath,
            String privateKeyPath)
    {
        super(publicKeyPath, privateKeyPath);
        gcpKeyHolder = new GCPSMEncryptorKeyHolder(projectId);
    }

    @SneakyThrows
    GCPSMJwtKeyHolder(
            String projectId,
            String publicKeyPath,
            String privateKeyPath,
            String publicKeyStrNotify,
            String privateKeyStrNotify)
    {
        super(publicKeyPath, privateKeyPath, publicKeyStrNotify, privateKeyStrNotify);
        gcpKeyHolder = new GCPSMEncryptorKeyHolder(projectId);
    }

    @Override
    protected String getKey(KeyPathHolder holder) {
        if(!holder.isKeySet())
            holder.setKey(gcpKeyHolder.getSecret(holder.getKeyPath()).replace("|", "\r\n"));
        return holder.getKey();
    }
}
