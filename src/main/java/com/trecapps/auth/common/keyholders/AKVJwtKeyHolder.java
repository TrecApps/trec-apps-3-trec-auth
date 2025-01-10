package com.trecapps.auth.common.keyholders;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.SecretProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Looks for Keys in the Specified Azure Key Vault
 */
public class AKVJwtKeyHolder extends IJwtKeyHolder {

    SecretClient keyVaultClient;

    HashMap<String, List<String>> versions = new HashMap<>();

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

    void refreshVersionList(String keyName){
        List<String> newVersionList = new ArrayList<>();
        keyVaultClient.listPropertiesOfSecretVersions(keyName).forEach((SecretProperties props) -> newVersionList.add(props.getVersion()));
        this.versions.put(keyName, newVersionList);
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
    protected String getKey(KeyPathHolder holder, int version){

        if(!versions.containsKey(holder.getKeyPath()))
            this.refreshVersionList(holder.getKeyPath());
        List<String> keyVersions = versions.get(holder.getKeyPath());

        if(!holder.isKeySet())
        {
            if(version == 0)
                holder.setKey(keyVaultClient.getSecret(holder.getKeyPath()).getValue().replace("|", "\r\n"));
            else if(version < keyVersions.size())
                holder.setKey(keyVaultClient.getSecret(holder.getKeyPath(), keyVersions.get(version)).getValue().replace("|", "\r\n"));
        }
        return holder.getKey();
    }

    @Override
    public void updateKey(String publicKey, String privateKey) {
        keyVaultClient.setSecret(this.basicPublic.getKeyPath(), publicKey);
        keyVaultClient.setSecret(this.basicPrivate.getKeyPath(), privateKey);
    }
}
