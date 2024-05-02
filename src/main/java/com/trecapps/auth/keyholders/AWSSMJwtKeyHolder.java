package com.trecapps.auth.keyholders;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;

public class AWSSMJwtKeyHolder implements IJwtKeyHolder{

    AWSSecretsManager client;
    String publicKeyPath;
    String privateKeyPath;

    String publicKey;
    String privateKey;

    AWSSMJwtKeyHolder(
            String publicKeyStr,
            String privateKeyStr,
            String endpoint,
            String region,
            String clientName,
            String clientSecret
    ){
        AwsClientBuilder.EndpointConfiguration  config  =  new  AwsClientBuilder.EndpointConfiguration(endpoint, region);
        AWSSecretsManagerClientBuilder clientBuilder  =  AWSSecretsManagerClientBuilder.standard();
        clientBuilder.setCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(clientName, clientSecret)));
        clientBuilder.setEndpointConfiguration(config);
        client = clientBuilder.build();

        this.privateKeyPath = privateKeyStr;
        this.publicKeyPath = publicKeyStr;
    }

    @Override
    public String getPublicKey() {
        if(publicKey == null)
        {
            publicKey = client.getSecretValue(new GetSecretValueRequest().withSecretId(publicKeyPath)).getSecretString();
        }
        return publicKey;
    }

    @Override
    public String getPrivateKey() {
        if(privateKey == null)
        {
            privateKey = client.getSecretValue(new GetSecretValueRequest().withSecretId(privateKeyPath)).getSecretString();
        }
        return privateKey.replace("|", "\r\n");
    }
}
