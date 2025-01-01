package com.trecapps.auth.common.keyholders;

import com.azure.core.http.rest.PagedIterable;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.trecapps.auth.RSATestHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
public class AKVJwtKeyHolderTest {

    AKVJwtKeyHolder keyHolder;

    @Mock
    SecretClient keyVaultClient;

    @BeforeEach
    void setUp(){

        try(MockedConstruction<SecretClientBuilder> mockedConstruction =
                    Mockito.mockConstruction(SecretClientBuilder.class, (mock, context)-> {
                        doReturn(mock).when(mock).vaultUrl(anyString());
                        doReturn(mock).when(mock).credential(any(ClientSecretCredential.class));
                        doReturn(keyVaultClient).when(mock).buildClient();
                    });
            MockedConstruction<ClientSecretCredentialBuilder> nestedMockedConstruction =
                    Mockito.mockConstruction(ClientSecretCredentialBuilder.class, (mock1,context1) -> {
                        doReturn(mock1).when(mock1).tenantId(anyString());
                        doReturn(mock1).when(mock1).clientId(anyString());
                        doReturn(mock1).when(mock1).clientSecret(anyString());
                        ClientSecretCredential credential = Mockito.mock(ClientSecretCredential.class);
                        doReturn(credential).when(mock1).build();
                    })){

            keyHolder = new AKVJwtKeyHolder(
                    "publicKey",
                    "privateKey",
                    "valut",
                    "tenant",
                    "client",
                    "secret"
            );

            KeyVaultSecret keyVaultSecretPrivate = Mockito.mock(KeyVaultSecret.class);
            KeyVaultSecret keyVaultSecretPublic = Mockito.mock(KeyVaultSecret.class);

            doReturn(RSATestHelper.privateKeyValue).when(keyVaultSecretPrivate).getValue();
            doReturn(RSATestHelper.publicKeyValue).when(keyVaultSecretPublic).getValue();

            PagedIterable<SecretProperties> mockIterable = Mockito.mock(PagedIterable.class);


            doReturn(mockIterable).when(keyVaultClient).listPropertiesOfSecretVersions("publicKey");
            doReturn(mockIterable).when(keyVaultClient).listPropertiesOfSecretVersions("privateKey");

            doReturn(keyVaultSecretPublic).when(keyVaultClient).getSecret("publicKey");
            doReturn(keyVaultSecretPrivate).when(keyVaultClient).getSecret("privateKey");
        }
    }

    @Test
    void testKeyHolder(){
        Assertions.assertEquals(RSATestHelper.privateKeyValue.replace("|", "\r\n"), this.keyHolder.getPrivateKey());
        Assertions.assertEquals(RSATestHelper.publicKeyValue, this.keyHolder.getPublicKey());
    }
}
