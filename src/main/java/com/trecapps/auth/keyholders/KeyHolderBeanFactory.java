package com.trecapps.auth.keyholders;

import com.trecapps.auth.services.web.IUserStorageService;
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
            @Value("${trec.key.private}") String privateKeyStr,
            @Value("${trec.key-notify.public:#{NULL}}") String publicKeyStrNotify,
            @Value("${trec.key-notify.private:#{NULL}}") String privateKeyStrNotify
    ) {
        if(publicKeyStrNotify != null && privateKeyStrNotify != null)
            return new StorageJwtKeyHolder(userStorageService, publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify);
        return new StorageJwtKeyHolder(userStorageService, publicKeyStr, privateKeyStr);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "AKV")
    IJwtKeyHolder getAKVJwtKeyHolder(
            @Value("${trec.jwt.vault-name}") String vaultName,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr,
            @Value("${trec.key-notify.public:#{NULL}}") String publicKeyStrNotify,
            @Value("${trec.key-notify.private:#{NULL}}") String privateKeyStrNotify,
            @Value("${trec.jwt.tenantId}") String tenantId,
            @Value("${trec.jwt.clientId}") String clientId,
            @Value("${trec.jwt.clientSecret}") String clientSecret
    ){
        if(publicKeyStrNotify != null && privateKeyStrNotify != null)
            return new AKVJwtKeyHolder(publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify, vaultName, tenantId, clientId, clientSecret);

        return new AKVJwtKeyHolder(publicKeyStr, privateKeyStr, vaultName, tenantId, clientId, clientSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "AWSSM")
    IJwtKeyHolder getAwsSecretsManagerJwtKeyHolder(
            @Value("${trec.jwt.endpoint}") String endpoint,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr,
            @Value("${trec.key-notify.public:#{NULL}}") String publicKeyStrNotify,
            @Value("${trec.key-notify.private:#{NULL}}") String privateKeyStrNotify,
            @Value("${trec.jwt.region}") String region,
            @Value("${trec.jwt.clientId}") String clientId,
            @Value("${trec.jwt.clientSecret}") String clientSecret
    )
    {
        if(publicKeyStrNotify != null && privateKeyStrNotify != null)
            return new AWSSMJwtKeyHolder(publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify, endpoint, region, clientId, clientSecret);
        return new AWSSMJwtKeyHolder(publicKeyStr, privateKeyStr, endpoint, region, clientId, clientSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.jwt.key-storage", name="strategy", havingValue = "GCPSM")
    IJwtKeyHolder getGcpSecretManagerJwtKeyHolder(
            @Value("${trec.jwt.project}") String project,
            @Value("${trec.key.public}") String publicKeyStr,
            @Value("${trec.key.private}") String privateKeyStr,
            @Value("${trec.key-notify.public:#{NULL}}") String publicKeyStrNotify,
            @Value("${trec.key-notify.private:#{NULL}}") String privateKeyStrNotify
    ) {
        if(publicKeyStrNotify != null && privateKeyStrNotify != null)
            return new GCPSMJwtKeyHolder(project, publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify);
        return new GCPSMJwtKeyHolder(project, publicKeyStr, privateKeyStr);
    }
}
