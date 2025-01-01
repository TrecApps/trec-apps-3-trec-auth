package com.trecapps.auth.common.keyholders;

import com.google.cloud.secretmanager.v1.*;
import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.List;

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

    public List<String> getSecretVersionList(String secretName) {
        List<String> ret = new ArrayList<>();
        client.listSecretVersions(SecretName.newBuilder()
                        .setSecret(secretName)
                        .setProject(projectName.getProject())
                .build()).iterateAll().forEach((SecretVersion sv) -> ret.add(sv.getName()));
        return ret;
    }

    public String getSecret(String secretName, String version) {
        SecretVersionName vName = SecretVersionName.newBuilder()
                .setSecret(secretName)
                .setProject(projectName.getProject())
                .setSecretVersion(version).build();
        AccessSecretVersionResponse response = client.accessSecretVersion(vName);

        return response.getPayload().getData().toStringUtf8();
    }
}
