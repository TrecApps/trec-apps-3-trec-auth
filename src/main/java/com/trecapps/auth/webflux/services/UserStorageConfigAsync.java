package com.trecapps.auth.webflux.services;

import com.trecapps.auth.encryptors.IFieldEncryptor;
import com.trecapps.auth.web.services.AwsS3UserStorageService;
import com.trecapps.auth.web.services.AzureBlobUserStorageService;
import com.trecapps.auth.web.services.GoogleCloudUserStorageService;
import com.trecapps.auth.web.services.IUserStorageService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

@Configuration
public class UserStorageConfigAsync {

    private static final String NULL_VALUE = "null";

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "Azure-key")
    IUserStorageServiceAsync getAzureUserServiceKey(
            @Value("${trecauth.storage.account-name}") String name,
            @Value("${trecauth.storage.account-key}") String key,
            @Value("${trecauth.storage.blob-endpoint}") String endpoint,
            @Value("${trecauth.storage.blob-container:trec-apps-users}") String containerName,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ) {
        return new AzureBlobUserStorageServiceAsync(name, key, endpoint, containerName, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "Azure-pwl")
    IUserStorageServiceAsync getAzureUserServicePwl(
            @Value("${trecauth.storage.blob-endpoint}") String endpoint,
            @Value("${trecauth.storage.blob-container:trec-apps-users}") String containerName,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ) {
        return new AzureBlobUserStorageServiceAsync(endpoint, containerName, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "AWS-S3-key")
    IUserStorageServiceAsync getAwsUserServiceKey(
            @Value("${trecauth.storage.account-name}") String name,
            @Value("${trecauth.storage.account-key}") String key,
            @Value("${trecauth.storage.s3-region}") String region,
            @Value("${trecauth.storage.s3-bucket}") String bucket,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        return new AwsS3UserStorageServiceAsync(name, key, region, bucket, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "AWS-S3-pwl")
    IUserStorageServiceAsync getAwsUserServicePwl(
            @Value("${trecauth.storage.s3-region}") String region,
            @Value("${trecauth.storage.s3-bucket}") String bucket,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        return new AwsS3UserStorageServiceAsync(region, bucket, app, fieldEncryptor, objectMapperBuilder);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.storage", name = "strategy", havingValue = "GCP-Storage")
    IUserStorageServiceAsync getGoogleUserService(
            @Value("${trecauth.storage.project-id}") String projectId,
            @Value("${trecauth.storage.bucket}")String bucketName,
            @Value("${trecauth.app}") String app,
            IFieldEncryptor fieldEncryptor,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ){
        return new GoogleCloudUserStorageServiceAsync(projectId, bucketName, app, fieldEncryptor, objectMapperBuilder);
    }
}
