package com.trecapps.auth.keyholders;

import com.google.cloud.secretmanager.v1.ProjectName;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import lombok.SneakyThrows;

public class GCPSMJwtKeyHolder extends GCPSMEncryptorKeyHolder implements IJwtKeyHolder{

    String publicKeyPath;
    String privateKeyPath;

    String publicKey;
    String privateKey;

    @SneakyThrows
    GCPSMJwtKeyHolder(
            String projectId,
            String publicKeyPath,
            String privateKeyPath)
    {
        super(projectId);
        client = SecretManagerServiceClient.create();
        projectName = ProjectName.of(projectId);
    }

    @Override
    public String getPublicKey() {
        if(publicKey == null){
            publicKey = getSecret(publicKeyPath);
        }
        return publicKey;
    }

    @Override
    public String getPrivateKey() {
        if(privateKey == null){
            privateKey = getSecret(privateKeyPath);
        }
        return privateKey;
    }
}
