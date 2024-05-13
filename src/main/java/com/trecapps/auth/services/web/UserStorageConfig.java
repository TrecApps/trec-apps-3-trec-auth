package com.trecapps.auth.services.web;

import com.trecapps.auth.encryptors.IFieldEncryptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

@Configuration
public class UserStorageConfig {

    private static final String NULL_VALUE = "null";

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "Azure-key")
    IUserStorageService getAzureUserServiceKey(
            @Value("${trecauth.storage.account-name}") String name,
            @Value("${trecauth.storage.account-key}") String key,
            @Value("${trecauth.storage.blob-endpoint}") String endpoint,
            @Value("${trecauth.storage.blob-container:trec-apps-users}") String containerName,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ) {
        return new AzureBlobUserStorageService(name, key, endpoint, containerName, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "Azure-pwl")
    IUserStorageService getAzureUserServicePwl(
            @Value("${trecauth.storage.blob-endpoint}") String endpoint,
            @Value("${trecauth.storage.blob-container:trec-apps-users}") String containerName,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ) {
        return new AzureBlobUserStorageService(endpoint, containerName, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "AWS-S3-key")
    IUserStorageService getAwsUserServiceKey(
            @Value("${trecauth.storage.account-name}") String name,
            @Value("${trecauth.storage.account-key}") String key,
            @Value("${trecauth.storage.s3-region}") String region,
            @Value("${trecauth.storage.s3-bucket}") String bucket,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        return new AwsS3UserStorageService(name, key, region, bucket, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "AWS-S3-pwl")
    IUserStorageService getAwsUserServicePwl(
            @Value("${trecauth.storage.s3-region}") String region,
            @Value("${trecauth.storage.s3-bucket}") String bucket,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        return new AwsS3UserStorageService(region, bucket, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "GCP-Storage")
    IUserStorageService getGoogleUserService(
            @Value("${trecauth.storage.project-id}") String projectId,
            @Value("${trecauth.storage.bucket}")String bucketName,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ){
        return new GoogleCloudUserStorageService(projectId, bucketName, app, fieldEncryptor, objectMapperBuilder);
    }
}
