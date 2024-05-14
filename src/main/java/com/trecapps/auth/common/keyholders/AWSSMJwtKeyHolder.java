package com.trecapps.auth.common.keyholders;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;

public class AWSSMJwtKeyHolder extends IJwtKeyHolder{

    AWSSecretsManager client;

    private void prepResource(String endpoint,
                              String region,
                              String clientName,
                              String clientSecret)
    {
        AwsClientBuilder.EndpointConfiguration  config  =  new  AwsClientBuilder.EndpointConfiguration(endpoint, region);
        AWSSecretsManagerClientBuilder clientBuilder  =  AWSSecretsManagerClientBuilder.standard();
        clientBuilder.setCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(clientName, clientSecret)));
        clientBuilder.setEndpointConfiguration(config);
        client = clientBuilder.build();
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
            holder.setKey(client.getSecretValue(new GetSecretValueRequest().withSecretId(holder.getKeyPath())).getSecretString().replace("|", "\r\n"));
        return holder.getKey();
    }
}
