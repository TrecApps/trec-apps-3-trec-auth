package com.trecapps.auth.common.keyholders;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
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

    private void prepClient(String vaultName){
        String vaultUri = String.format("https://%s.vault.azure.net/", vaultName);
        this.keyVaultClient = new SecretClientBuilder().vaultUrl(vaultUri)
                .credential(new DefaultAzureCredentialBuilder()
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

    public AKVJwtKeyHolder(String publicKeyStr,
                           String privateKeyStr,
                           String vaultName){
        super(publicKeyStr, privateKeyStr);
        prepClient(vaultName);
    }

    void refreshVersionList(String keyName){
        List<SecretProperties> newVersionList = new ArrayList<>();
        keyVaultClient.listPropertiesOfSecretVersions(keyName).forEach(newVersionList::add);

        this.versions
                .put(keyName, newVersionList.stream()
                        .sorted((SecretProperties sp1, SecretProperties sp2) ->
                                sp2.getCreatedOn().compareTo(sp1.getCreatedOn()))
                        .map(SecretProperties::getVersion).toList());
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

    public AKVJwtKeyHolder(
            String publicKeyStr,
            String privateKeyStr,
            String publicKeyStrNotify,
            String privateKeyStrNotify,
            String vaultName)
    {
        super(publicKeyStr, privateKeyStr, publicKeyStrNotify, privateKeyStrNotify);
        prepClient(vaultName);
    }

    @Override
    protected String getKey(KeyPathHolder holder, int version){

        if(!versions.containsKey(holder.getKeyPath()))
            this.refreshVersionList(holder.getKeyPath());
        List<String> keyVersions = versions.get(holder.getKeyPath());


        if(version < keyVersions.size())
        {
            if(version == 0){
                // Get the latest version
                holder.setKey(keyVaultClient.getSecret(holder.getKeyPath()).getValue().replace("|", "\r\n"));

            } else {
                // During start up, get a previous version
                holder.setKey(keyVaultClient.getSecret(holder.getKeyPath(), keyVersions.get(version)).getValue().replace("|", "\r\n"));
            }
        }

        
        return holder.getKey();
    }

    @Override
    public void updateKey(String publicKey, String privateKey) {
        keyVaultClient.setSecret(this.basicPublic.getKeyPath(), publicKey);
        keyVaultClient.setSecret(this.basicPrivate.getKeyPath(), privateKey);
    }
}
