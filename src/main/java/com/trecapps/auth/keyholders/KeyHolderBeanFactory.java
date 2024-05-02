package com.trecapps.auth.keyholders;

import com.trecapps.auth.services.core.IUserStorageService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeyHolderBeanFactory {

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "blob")
    IJwtKeyHolder getBlobJwtKeyHolder(
            IUserStorageService userStorageService,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr
    ) {
        return new StorageJwtKeyHolder(userStorageService, publicKeyStr, privateKeyStr);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "AKV")
    IJwtKeyHolder getAKVJwtKeyHolder(
            @Value("${trec.jwt.vault-name}") String vaultName,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr,
            @Value("${trec.jwt.tenantId}") String tenantId,
            @Value("${trec.jwt.clientId}") String clientId,
            @Value("${trec.jwt.clientSecret}") String clientSecret
    ){
        return new AKVJwtKeyHolder(vaultName, publicKeyStr, privateKeyStr, tenantId, clientId, clientSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "AWSSM")
    IJwtKeyHolder getAwsSecretsManagerJwtKeyHolder(
            @Value("${trec.jwt.endpoint}") String endpoint,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr,
            @Value("${trec.jwt.region}") String region,
            @Value("${trec.jwt.clientId}") String clientId,
            @Value("${trec.jwt.clientSecret}") String clientSecret
    )
    {
        return new AWSSMJwtKeyHolder(publicKeyStr, privateKeyStr, endpoint, region, clientId, clientSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "GCPSM")
    IJwtKeyHolder getGcpSecretManagerJwtKeyHolder(
            @Value("${trec.jwt.project}") String project,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr
    ) {
        return new GCPSMJwtKeyHolder(project, publicKeyStr, privateKeyStr);
    }
}
