package com.trecapps.auth.common.keyholders;


import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.util.Optional;

public class AWSSMJwtKeyHolder extends IJwtKeyHolder{

    SecretsManagerClient client;
    String secretContainer;

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



    @Override
    protected String getKey(KeyPathHolder holder) {
        if(!holder.isKeySet())
        {
            GetSecretValueRequest request = GetSecretValueRequest.builder()
                    .secretId(secretContainer)
                    .build();
            Optional<String> ret = client.getSecretValue(request).getValueForField(holder.getKeyPath(), String.class);
            ret.ifPresent(holder::setKey);
        }

        return holder.getKey();
    }
}
