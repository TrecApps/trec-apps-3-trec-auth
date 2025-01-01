package com.trecapps.auth.common.keyholders;

import com.azure.security.keyvault.secrets.models.SecretProperties;
import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class GCPSMJwtKeyHolder extends IJwtKeyHolder{

    GCPSMEncryptorKeyHolder gcpKeyHolder;

    HashMap<String, List<String>> versions = new HashMap<>();

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

    void refreshVersionList(String keyName){
        this.versions.put(keyName, this.gcpKeyHolder.getSecretVersionList(keyName));
    }

    @Override
    protected String getKey(KeyPathHolder holder, int version) {
        if(!versions.containsKey(holder.getKeyPath()))
            this.refreshVersionList(holder.getKeyPath());
        List<String> keyVersions = versions.get(holder.getKeyPath());

        if(!holder.isKeySet()) {
            if (version == 0)
                holder.setKey(gcpKeyHolder.getSecret(holder.getKeyPath()).replace("|", "\r\n"));
            else if(version < keyVersions.size())
                holder.setKey(gcpKeyHolder.getSecret(holder.getKeyPath(), keyVersions.get(version)).replace("|", "\r\n"));
        }
        return holder.getKey();
    }
}
