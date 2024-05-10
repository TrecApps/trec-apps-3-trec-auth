package com.trecapps.auth.keyholders;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.trecapps.auth.services.core.RsaKeyPair;

import java.time.OffsetDateTime;
import java.util.Timer;

/**
 * Looks for Keys in the Specified Azure Key Vault
 */
public class AKVJwtKeyHolder extends IJwtKeyHolder {

    SecretClient keyVaultClient;

    private void prepClient(String vaultName,
                            String tenantId,
                            String clientId,
                            String clientSecret){
        String vaultUri = String.format("https://%s.vault.azure.net/", vaultName);
        this.keyVaultClient = new SecretClientBuilder().vaultUrl(vaultUri)
                .credential(new ClientSecretCredentialBuilder()
                        .tenantId(tenantId)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build())
                .buildClient();
    }

    public AKVJwtKeyHolder(
            String publicKeyStr,
            String privateKeyStr,
            String vaultName,
            String tenantId,
            String clientId,
            String clientSecret)
    {
        super(publicKeyStr, privateKeyStr);
        prepClient(vaultName, tenantId, clientId, clientSecret);
    }

    public AKVJwtKeyHolder(
            String publicKeyStr,
            String privateKeyStr,
            String publicKeyStrNotify,
            String privateKeyStrNotify,
            String vaultName,
            String tenantId,
            String clientId,
            String clientSecret)
    {
        super(publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify);
        prepClient(vaultName, tenantId, clientId, clientSecret);
    }

    @Override
    protected String getKey(KeyPathHolder holder){
        if(!holder.isKeySet())
        {
            holder.setKey(keyVaultClient.getSecret(holder.getKeyPath()).getValue());
        }
        return holder.getKey();
    }
}
