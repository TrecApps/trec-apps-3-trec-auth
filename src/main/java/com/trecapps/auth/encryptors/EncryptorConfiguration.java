package com.trecapps.auth.encryptors;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EncryptorConfiguration {

    @ConditionalOnMissingBean(IFieldEncryptor.class)
    public IFieldEncryptor getDefaultEncryptor(){
        return new BasicFieldEncryptor();
    }


}
