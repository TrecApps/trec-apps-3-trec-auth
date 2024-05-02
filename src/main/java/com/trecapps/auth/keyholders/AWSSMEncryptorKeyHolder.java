package com.trecapps.auth.keyholders;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;

public class AWSSMEncryptorKeyHolder implements IEncryptorKeyHolder {

    AWSSecretsManager client;

    public AWSSMEncryptorKeyHolder(
            String endpoint,
            String region,
            String clientName,
            String clientSecret
    ){
        AwsClientBuilder.EndpointConfiguration  config  =  new  AwsClientBuilder.EndpointConfiguration(endpoint, region);
        AWSSecretsManagerClientBuilder  clientBuilder  =  AWSSecretsManagerClientBuilder.standard();
        clientBuilder.setCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(clientName, clientSecret)));
        clientBuilder.setEndpointConfiguration(config);
        client = clientBuilder.build();
    }

    @Override
    public String getSecret(String secretName) {
        return client.getSecretValue(new GetSecretValueRequest().withSecretId(secretName)).getSecretString();
    }
}
