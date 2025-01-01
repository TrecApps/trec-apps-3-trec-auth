package com.trecapps.auth.common.keyholders;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretVersionIdsRequest;
import software.amazon.awssdk.services.secretsmanager.model.SecretVersionsListEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class AWSSMJwtKeyHolder extends IJwtKeyHolder{

    SecretsManagerClient client;
    String secretContainer;

    TypeReference<HashMap<String,Object>> typeRef
            = new TypeReference<HashMap<String,Object>>() {};
    ObjectMapper mapper = new ObjectMapper();

    HashMap<String, List<String>> versions = new HashMap<>();

    private void prepResource(String secretContainer,
                              String region,
                              String clientName,
                              String clientSecret)
    {
        client = SecretsManagerClient.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(clientName, clientSecret)
                ))
                .region(Region.of(region))
                .build();
        this.secretContainer = secretContainer;
    }

    AWSSMJwtKeyHolder(
            String publicKeyStr,
            String privateKeyStr,
            String endpoint,
            String region,
            String clientName,
            String clientSecret
    ){
        super(publicKeyStr, privateKeyStr);
        prepResource(endpoint, region, clientName, clientSecret);
    }

    AWSSMJwtKeyHolder(
            String publicKeyStr,
            String privateKeyStr,
            String publicKeyStrNotify,
            String privateKeyStrNotify,
            String endpoint,
            String region,
            String clientName,
            String clientSecret
    ){
        super(publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify);
        prepResource(endpoint, region, clientName, clientSecret);
    }

    void refreshVersionList(String keyName){
        List<String> newVersionList = new ArrayList<>();
        ListSecretVersionIdsRequest request = ListSecretVersionIdsRequest.builder()
                .secretId(keyName)
                .build();
        client.listSecretVersionIds(request).versions()
                .forEach((SecretVersionsListEntry entry) -> newVersionList.add(entry.versionId()));
        this.versions.put(keyName, newVersionList);
    }


    @SneakyThrows
    @Override
    protected String getKey(KeyPathHolder holder, int version) {
        if(!versions.containsKey(holder.getKeyPath()))
            this.refreshVersionList(holder.getKeyPath());
        List<String> keyVersions = versions.get(holder.getKeyPath());
        if(!holder.isKeySet())
        {
            GetSecretValueRequest request;
            if(version == 0)
                request = GetSecretValueRequest.builder()
                    .secretId(secretContainer)
                    .build();
            else if (version < keyVersions.size())
                request = GetSecretValueRequest.builder()
                        .secretId(secretContainer)
                        .versionId(keyVersions.get(version))
                        .build();
            else return null;

            String secret = client.getSecretValue(request).secretString();
            HashMap<String,Object> values = mapper.readValue(secret, typeRef);
            Object o = values.get(holder.getKeyPath());
            if(o != null)
                holder.setKey(o.toString().replace("|", "\r\n"));
        }

        return holder.getKey();
    }
}
