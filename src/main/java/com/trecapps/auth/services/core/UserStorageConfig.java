package com.trecapps.auth.services.core;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

@Configuration
public class UserStorageConfig {

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "Azure-sas")
    IUserStorageService getAzureUserService(
            @Value("${trecauth.storage.account-name}") String name,
            @Value("${trecauth.storage.account-key}") String key,
            @Value("${trecauth.storage.blob-endpoint}") String endpoint,
            @Value("${trecauth.storage.blob-container:trec-apps-users}") String containerName,
            @Value("${trecauth.app}") String app,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ) {
        return new AzureBlobUserStorageService(name, key, endpoint, containerName, app, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "AWS-S3")
    IUserStorageService getAwsUserService(
            @Value("${trecauth.storage.account-name}") String name,
            @Value("${trecauth.storage.account-key}") String key,
            @Value("${trecauth.storage.s3-endpoint}") String endpoint,
            @Value("${trecauth.storage.s3-region}") String region,
            @Value("${trecauth.storage.s3-bucket}") String bucket,
            @Value("${trecauth.app}") String app,
            Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        return new AwsS3UserStorageService(name, key, endpoint, region, bucket, app, objectMapperBuilder);
    }
}
