package com.trecapps.auth.keyholders;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

import java.time.OffsetDateTime;
import java.util.Timer;

/**
 * Looks for Keys in the Specified Azure Key Vault
 */
public class AKVJwtKeyHolder implements IJwtKeyHolder {

    SecretClient keyVaultClient;


    String publicKeyPath;
    String privateKeyPath;

    String publicKey;
    String privateKey;
    public AKVJwtKeyHolder(
            String vaultName,
            String publicKeyStr,
            String privateKeyStr,
            String tenantId,
            String clientId,
            String clientSecret)
    {
        String vaultUri = String.format("https://%s.vault.azure.net/", vaultName);
        this.keyVaultClient = new SecretClientBuilder().vaultUrl(vaultUri)
                .credential(new ClientSecretCredentialBuilder()
                        .tenantId(tenantId)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build())
                .buildClient();
        this.privateKeyPath = privateKeyStr;
        this.publicKeyPath = publicKeyStr;
    }

    @Override
    public String getPublicKey() {
        if(publicKey == null)
        {
            publicKey = keyVaultClient.getSecret(publicKeyPath).getValue();
        }
        return publicKey;
    }

    @Override
    public String getPrivateKey() {
        if(privateKey == null)
        {
            privateKey = keyVaultClient.getSecret(privateKeyPath).getValue();
        }
        return privateKey.replace("|", "\r\n");
    }
}
