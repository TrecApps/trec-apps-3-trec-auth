package com.trecapps.auth.common.encryptors;

import com.azure.spring.cloud.autoconfigure.implementation.condition.ConditionalOnMissingProperty;
import com.trecapps.auth.common.keyholders.AKVEncryptorKeyHolder;
import com.trecapps.auth.common.keyholders.AWSSMEncryptorKeyHolder;
import com.trecapps.auth.common.keyholders.GCPSMEncryptorKeyHolder;
import com.trecapps.auth.common.keyholders.IEncryptorKeyHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EncryptorConfiguration {

    @Bean
    @ConditionalOnMissingProperty(prefix = "trecauth.encryption", name = "strategy")
    public IFieldEncryptor getDefaultEncryptor(){
        return new BasicFieldEncryptor();
    }

    @Bean
    @ConditionalOnProperty(prefix="trecauth.key-holder", name="type", havingValue = "azure-key-vault")
    IEncryptorKeyHolder getAzureEncryptorKeyHolder(
            @Value("${trecauth.keyvault.name}") String vaultName,
            @Value("${trecauth.keyvault.tenantId}") String tenantId,
            @Value("${trecauth.keyvault.clientId}") String clientId,
            @Value("${trecauth.keyvault.clientSecret}") String clientSecret
    ) {
        return new AKVEncryptorKeyHolder(vaultName, tenantId, clientId, clientSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix="trecauth.key-holder", name="type", havingValue = "aws-secrets-manager")
    IEncryptorKeyHolder getAWSEncryptorKeyHolder(
        @Value("${trecauth.secrets-manager.region}") String region,
        @Value("${trecauth.secrets-manager.secret}") String secret,
        @Value("${trecauth.secrets-manager.clientName}") String clientName,
        @Value("${trecauth.secrets-manager.clientSecret}") String clientSecret
    ){
        return new AWSSMEncryptorKeyHolder(secret, region, clientName, clientSecret);
    }

    @Bean
    @ConditionalOnProperty(prefix="trecauth.key-holder", name="type", havingValue = "gcp-secret-manager")
    IEncryptorKeyHolder getGCPEncryptorKeyHolder(
            @Value("${trecauth.secret-manager.project}")String project
    ){
        return new GCPSMEncryptorKeyHolder(project);
    }


    @Bean
    @ConditionalOnProperty(prefix = "trecauth.encryption", name="strategy", havingValue = "RSA")
    IFieldEncryptor getRsaEncryptor(
            IEncryptorKeyHolder keyHolder,
            @Value("${trecauth.encryptor.rsa.public-name}") String publicKey,
            @Value("${trecauth.encryptor.rsa.private-name}") String privateKey
    ){
        return new RsaFieldEncryptor(keyHolder, publicKey, privateKey);
    }

    @Bean
    @ConditionalOnProperty(prefix = "trecauth.encryption", name="strategy", havingValue = "AES")
    IFieldEncryptor getAesEncryptor(
            IEncryptorKeyHolder keyHolder,
            @Value("${trecauth.encryptor.aes.password}") String password,
            @Value("${trecauth.encryptor.aes.salt}") String salt,
            @Value("${trecauth.encryptor.aes.iv}") String iv
    ){
        return new AesFieldEncryptor(keyHolder, password, salt, iv);
    }

}
