package com.trecapps.auth.common.keyholders;

import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.google.protobuf.ByteString;
import com.trecapps.auth.RSATestHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.Charset;

import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
public class GCPSMJwtKeyHolderTest {

    GCPSMJwtKeyHolder keyHolder;

    @Mock
    SecretManagerServiceClient client;

    @BeforeEach
    void setUp(){
        try(MockedStatic<SecretManagerServiceClient> smms = Mockito.mockStatic(SecretManagerServiceClient.class))
        {
            smms.when(SecretManagerServiceClient::create).thenReturn(client);
            keyHolder = new GCPSMJwtKeyHolder(
                    "project",
                    "public",
                    "private");
        }

        AccessSecretVersionResponse responsePublic = Mockito.mock(AccessSecretVersionResponse.class);
        AccessSecretVersionResponse responsePrivate = Mockito.mock(AccessSecretVersionResponse.class);

        SecretPayload payloadPublic = Mockito.mock(SecretPayload.class);
        SecretPayload payloadPrivate = Mockito.mock(SecretPayload.class);

        ByteString strPublic = ByteString.copyFrom(RSATestHelper.publicKeyValue, Charset.defaultCharset());
        ByteString strPrivate = ByteString.copyFrom(RSATestHelper.privateKeyValue.replace("|", "\r\n"), Charset.defaultCharset());

        Mockito.doReturn(strPublic).when(payloadPublic).getData();
        Mockito.doReturn(strPrivate).when(payloadPrivate).getData();

        Mockito.doReturn(payloadPrivate).when(responsePrivate).getPayload();
        Mockito.doReturn(payloadPublic).when(responsePublic).getPayload();

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            SecretVersionName name = invoke.getArgument(0, SecretVersionName.class);

            if("public".equals(name.getSecret()))
                return responsePublic;
            else return responsePrivate;
        }).when(client).accessSecretVersion(any(SecretVersionName.class));
    }

    @Test
    void testKeyHolder(){
        Assertions.assertEquals(RSATestHelper.privateKeyValue.replace("|", "\r\n"), this.keyHolder.getPrivateKey());
        Assertions.assertEquals(RSATestHelper.publicKeyValue, this.keyHolder.getPublicKey());
    }
}
