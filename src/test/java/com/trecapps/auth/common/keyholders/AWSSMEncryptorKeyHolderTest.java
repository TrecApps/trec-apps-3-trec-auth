package com.trecapps.auth.common.keyholders;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trecapps.auth.RSATestHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
public class AWSSMEncryptorKeyHolderTest {

    AWSSMEncryptorKeyHolder keyHolder;

    @Mock
    SecretsManagerClient client;

    @BeforeEach
    void setUp() throws JsonProcessingException {

        try(MockedStatic<SecretsManagerClient> smMock = Mockito.mockStatic(SecretsManagerClient.class))
        {
            SecretsManagerClientBuilder builder = Mockito.mock(SecretsManagerClientBuilder.class);
            smMock.when(SecretsManagerClient::builder).thenReturn(builder);
            Mockito.doReturn(builder).when(builder).credentialsProvider(any(AwsCredentialsProvider.class));
            Mockito.doReturn(builder).when(builder).region(any(Region.class));
            Mockito.doReturn(client).when(builder).build();
            keyHolder = new AWSSMEncryptorKeyHolder(
                    "containers",
                    Region.US_EAST_1.toString(),
                    "client",
                    "secret"
            );
        }
        HashMap<String, Object> map = new HashMap<>();
        map.put("private", RSATestHelper.privateKeyValue.replace("|", "\r\n"));
        map.put("public", RSATestHelper.publicKeyValue);
        String secretMap = new ObjectMapper().writeValueAsString(map);

        GetSecretValueResponse response = Mockito.mock(GetSecretValueResponse.class);
        Mockito.doReturn(secretMap).when(response).secretString();
        Mockito.doReturn(response).when(client).getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void test(){
        Assertions.assertEquals(RSATestHelper.privateKeyValue.replace("|", "\r\n"), this.keyHolder.getSecret("private"));
        Assertions.assertEquals(RSATestHelper.publicKeyValue, this.keyHolder.getSecret("public"));
    }
}
