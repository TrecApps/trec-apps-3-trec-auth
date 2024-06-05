package com.trecapps.auth.common.keyholders;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.util.HashMap;

public class AWSSMEncryptorKeyHolder implements IEncryptorKeyHolder {

    SecretsManagerClient client;
    String secretContainer;

    TypeReference<HashMap<String,Object>> typeRef
            = new TypeReference<HashMap<String,Object>>() {};
    ObjectMapper mapper = new ObjectMapper();

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
    @SneakyThrows
    public String getSecret(String secretName) {
        GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId(secretContainer)
                .build();
        String secret = client.getSecretValue(request).secretString();
        HashMap<String,Object> values = mapper.readValue(secret, typeRef);
        Object o = values.get(secretName);
        return o == null ? null : o.toString();
    }
}
