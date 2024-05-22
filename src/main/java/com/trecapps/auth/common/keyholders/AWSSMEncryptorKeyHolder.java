package com.trecapps.auth.common.keyholders;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.util.Optional;

public class AWSSMEncryptorKeyHolder implements IEncryptorKeyHolder {

    SecretsManagerClient client;
    String secretContainer;

    public AWSSMEncryptorKeyHolder(
            String secretContainer,
            String region,
            String clientName,
            String clientSecret
    ){
        client = SecretsManagerClient.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(clientName, clientSecret)
                ))
                .region(Region.of(region))
                .build();
        this.secretContainer = secretContainer;
    }

    @Override
    public String getSecret(String secretName) {
        GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId(secretContainer)
                .build();
        Optional<String> ret = client.getSecretValue(request).getValueForField(secretName, String.class);
        return ret.orElse(null);
    }
}
