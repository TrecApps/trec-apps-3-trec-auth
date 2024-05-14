package com.trecapps.auth.common.keyholders;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

public class AKVEncryptorKeyHolder implements IEncryptorKeyHolder {

    SecretClient keyVaultClient;

    public AKVEncryptorKeyHolder(
            String vaultName,
            String tenantId,
            String clientId,
            String clientSecret
    ){
        String vaultUri = String.format("https://%s.vault.azure.net/", vaultName);
        this.keyVaultClient = new SecretClientBuilder().vaultUrl(vaultUri)
                .credential(new ClientSecretCredentialBuilder()
                        .tenantId(tenantId)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build())
                .buildClient();
    }

    @Override
    public String getSecret(String secretName) {
        return keyVaultClient.getSecret(secretName).getValue();
    }
}
