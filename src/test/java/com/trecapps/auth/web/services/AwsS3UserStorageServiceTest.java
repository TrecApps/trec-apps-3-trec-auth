package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.models.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.OffsetDateTime;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
public class AwsS3UserStorageServiceTest {

    AwsS3UserStorageService storageService;

    @Mock
    S3Client client;

    @Mock
    IFieldEncryptor encryptor;

    ObjectMapper mapper;

    @BeforeEach
    void setUpTests() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        S3ClientBuilder clientBuilder = Mockito.mock(S3ClientBuilder.class);

        try(
                MockedStatic<S3Client> mockBuilderStatic = Mockito.mockStatic(S3Client.class, (InvocationOnMock invocation) -> clientBuilder);
                )
        {
            Mockito.doReturn(clientBuilder).when(clientBuilder).credentialsProvider(Mockito.any());
            Mockito.doReturn(clientBuilder).when(clientBuilder).region(Mockito.any(Region.class));

            Mockito.doReturn(client).when(clientBuilder).build();

            Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();

            this.storageService = new AwsS3UserStorageService(
                    "client",
                    "secret",
                    Region.US_EAST_1.id(),
                    "some-Buket-name",
                    "trec-apps",
                    encryptor,
                    objectMapperBuilder);
        }

        mapper = new Jackson2ObjectMapperBuilder().createXmlMapper(false).build();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    }

    @Test
    void testRetrieveKey() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        Mockito.doReturn(new byte[]{
                'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'
        }).when(mockResponse).readAllBytes();

        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));

        String result = this.storageService.retrieveKey("some Key");

        Assertions.assertEquals("Hello World!", result);
    }

    @Test
    void testRetrieveUser() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        TcUser user = ObjectTestProvider.getTcUser();

        byte[] userAsBytes = mapper.writeValueAsBytes(user);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(TcUser.class));

        TcUser returnedUser = this.storageService.retrieveUser("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(user, returnedUser);

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedUser = this.storageService.retrieveUser("id");
        Assertions.assertNull(returnedUser);
    }

    @Test
    void testGetAccountById() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        TcUser user = ObjectTestProvider.getTcUser();

        byte[] userAsBytes = mapper.writeValueAsBytes(user);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(TcUser.class));

        Optional<TcUser> returnedUser = this.storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isPresent());
        Assertions.assertEquals(user, returnedUser.get());

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedUser = this.storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isEmpty());
    }

    @Test
    void testRetrieveSessions() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        SessionList sessionList = new SessionList();
        sessionList.addNewSession(
                "Trec-Apps",
                "FireFox",
                null);

        byte[] userAsBytes = mapper.writeValueAsBytes(sessionList);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(sessionList).when(encryptor).decrypt(Mockito.any(SessionList.class));

        SessionList returnedSessions = this.storageService.retrieveSessions("id");
        Assertions.assertNotNull(returnedSessions);
        Assertions.assertEquals(sessionList, returnedSessions);

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedSessions = this.storageService.retrieveSessions("id");
        Assertions.assertNull(returnedSessions);
    }

    @Test
    void testRetrieveSessionsV2() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        SessionListV2 sessionList = new SessionListV2();


        byte[] userAsBytes = mapper.writeValueAsBytes(sessionList);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(sessionList).when(encryptor).decrypt(Mockito.any(SessionListV2.class));

        SessionListV2 returnedSessions = this.storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedSessions);
        Assertions.assertEquals(sessionList, returnedSessions);

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedSessions = this.storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedSessions);
    }

    @Test
    void testGetBrandById() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        TcBrands brand = ObjectTestProvider.getBrand();


        byte[] userAsBytes = mapper.writeValueAsBytes(brand);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(TcBrands.class));

        Optional<TcBrands> returnedUser = this.storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isPresent());
        Assertions.assertEquals(brand, returnedUser.get());

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedUser = this.storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isEmpty());
    }

    @Test
    void testRetrieveBrand() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        TcBrands brand = ObjectTestProvider.getBrand();


        byte[] userAsBytes = mapper.writeValueAsBytes(brand);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(TcBrands.class));

        TcBrands returnedUser = this.storageService.retrieveBrand("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedUser = this.storageService.retrieveBrand("id");
        Assertions.assertNull(returnedUser);
    }

    @Test
    void testRetrieveAppLocker() throws IOException {
        ResponseInputStream<GetObjectResponse> mockResponse = Mockito.mock(ResponseInputStream.class);

        AppLocker brand = new AppLocker();


        byte[] userAsBytes = mapper.writeValueAsBytes(brand);
        Mockito.doReturn(userAsBytes).when(mockResponse).readAllBytes();
        Mockito.doReturn(mockResponse).when(client).getObject(Mockito.any(GetObjectRequest.class));
        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(AppLocker.class));

        AppLocker returnedUser = this.storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doThrow(NoSuchKeyException.class).when(client).getObject(Mockito.any(GetObjectRequest.class));
        returnedUser = this.storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);
    }

    @Test
    void testSaveLogins(){
        AppLocker brand = new AppLocker();

        Mockito.doReturn(brand).when(encryptor).encrypt(brand);
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            RequestBody body = invoke.getArgument(1, RequestBody.class);
            try(InputStream stream = body.contentStreamProvider().newStream())
            {
                byte[] bytes = stream.readAllBytes();
                AppLocker locker = mapper.readValue(bytes, AppLocker.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(brand, locker);
            }

            return null;
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(RequestBody.class));

        this.storageService.saveLogins(brand, "id");
    }

    @Test
    void testSaveBrand(){
        TcBrands brand = ObjectTestProvider.getBrand();

        Mockito.doReturn(brand).when(encryptor).encrypt(brand);
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            RequestBody body = invoke.getArgument(1, RequestBody.class);
            try(InputStream stream = body.contentStreamProvider().newStream())
            {
                byte[] bytes = stream.readAllBytes();
                TcBrands locker = mapper.readValue(bytes, TcBrands.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(brand, locker);
            }

            return null;
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(RequestBody.class));

        this.storageService.saveBrand(brand);
    }

    @Test
    @Disabled("SessionList class should be deprecated")
    void testSaveSession(){
        SessionList sessionList = new SessionList();
        sessionList.addNewSession(
                "Trec-Apps",
                "FireFox",
                null);


        Mockito.doReturn(sessionList).when(encryptor).encrypt(sessionList);
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            RequestBody body = invoke.getArgument(1, RequestBody.class);
            try(InputStream stream = body.contentStreamProvider().newStream())
            {
                byte[] bytes = stream.readAllBytes();
                SessionList locker = mapper.readValue(bytes, SessionList.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(sessionList, locker);
            }

            return null;
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(RequestBody.class));

        this.storageService.saveSessions(sessionList, "id");
    }

    @Test
    void testSaveUserV2(){
        SessionListV2 sessions = new SessionListV2();

        Mockito.doReturn(sessions).when(encryptor).encrypt(sessions);
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            RequestBody body = invoke.getArgument(1, RequestBody.class);
            try(InputStream stream = body.contentStreamProvider().newStream())
            {
                byte[] bytes = stream.readAllBytes();
                SessionListV2 locker = mapper.readValue(bytes, SessionListV2.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(sessions, locker);
            }

            return null;
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(RequestBody.class));

        this.storageService.saveSessions(sessions, "id");
    }

    @Test
    void testSaveUser(){
        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn(user).when(encryptor).encrypt(user);
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            RequestBody body = invoke.getArgument(1, RequestBody.class);
            try(InputStream stream = body.contentStreamProvider().newStream())
            {
                byte[] bytes = stream.readAllBytes();
                TcUser locker = mapper.readValue(bytes, TcUser.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(user, locker);
            }

            return null;
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(RequestBody.class));

        this.storageService.saveUser(user);
    }
}
