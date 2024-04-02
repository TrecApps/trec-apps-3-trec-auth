package com.trecapps.auth.encryptors;

import com.trecapps.auth.keyholders.AKVEncryptorKeyHolder;
import com.trecapps.auth.keyholders.IEncryptorKeyHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EncryptorConfiguration {

    @ConditionalOnMissingBean(IFieldEncryptor.class)
    @Bean
    public IFieldEncryptor getDefaultEncryptor(){
        return new BasicFieldEncryptor();
    }

    private IEncryptorKeyHolder getEncryptorKeyHolder(
            String vaultName,
            String tenantId,
            String clientId,
            String clientSecret
    ) {
        return new AKVEncryptorKeyHolder(vaultName, tenantId, clientId, clientSecret);
    }

//    @Bean
//    @ConditionalOnProperty(prefix = "trecauth.encryption", name="strategy", havingValue = "RSA")
//    IFieldEncryptor getRsaEncryptor(
//            @Value("trecauth.keyvault.name") String vaultName,
//            @Value("trecauth.keyvault.tenantId") String tenantId,
//            @Value("trecauth.keyvault.clientId") String clientId,
//            @Value("trecauth.keyvault.clientSecret") String clientSecret,
//            @Value("trecauth.keyvault.rsa.public-name") String publicKey,
//            @Value("trecauth.keyvault.rsa.public-name") String privateKey
//    ){
//        IEncryptorKeyHolder keyHolder = getEncryptorKeyHolder(vaultName, tenantId, clientId, clientSecret);
//
//    }
//
//    @Bean
//    @ConditionalOnProperty(prefix = "trecauth.encryption", name="strategy", havingValue = "AES")
//    IFieldEncryptor getAesEncryptor(
//            @Value("trecauth.keyvault.name") String vaultName,
//            @Value("trecauth.keyvault.tenantId") String tenantId,
//            @Value("trecauth.keyvault.clientId") String clientId,
//            @Value("trecauth.keyvault.clientSecret") String clientSecret,
//            @Value("trecauth.keyvault.aes-name") String keyName
//    ){
//        IEncryptorKeyHolder keyHolder = getEncryptorKeyHolder(vaultName, tenantId, clientId, clientSecret);
//
//    }

}
