package com.trecapps.auth.common.keyholders;

import com.google.cloud.secretmanager.v1.*;
import lombok.SneakyThrows;

public class GCPSMEncryptorKeyHolder implements IEncryptorKeyHolder{

    SecretManagerServiceClient client;
    ProjectName projectName;

    @SneakyThrows
    public GCPSMEncryptorKeyHolder(String projectId)
    {
        client = SecretManagerServiceClient.create();
        projectName = ProjectName.of(projectId);

    }


    @Override
    public String getSecret(String secretName) {
        SecretVersionName vName = SecretVersionName.newBuilder()
                .setSecret(secretName)
                .setProject(projectName.getProject())
                .setSecretVersion("latest").build();
        AccessSecretVersionResponse response = client.accessSecretVersion(vName);

        return response.getPayload().getData().toStringUtf8();
    }
}
