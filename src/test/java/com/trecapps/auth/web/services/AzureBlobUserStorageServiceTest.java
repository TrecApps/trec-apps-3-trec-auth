package com.trecapps.auth.web.services;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.util.BinaryData;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.TcBrands;
import com.trecapps.auth.common.models.TcUser;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AzureBlobUserStorageServiceTest {

    AzureBlobUserStorageService storageService;

    @Mock
    BlobServiceClientBuilder clientBuilder;
    @Mock
    BlobServiceClient blobServiceClient;
    @Mock
    BlobContainerClient containerClient;
    @Mock
    IFieldEncryptor encryptor;
    @Mock
    BlobClient client;

    ObjectMapper mapper;


    @BeforeEach
    void prepService()
    {
        Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();

        mapper = objectMapperBuilder.createXmlMapper(false).build();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        try(MockedConstruction<BlobServiceClientBuilder> construction =
                    Mockito.mockConstruction(BlobServiceClientBuilder.class, (mock,context)-> {
                        doReturn(mock).when(mock).credential(any(AzureNamedKeyCredential.class));
                        doReturn(mock).when(mock).endpoint(anyString());
                        doReturn(blobServiceClient).when(mock).buildClient();
                    })){
            Mockito.doReturn(containerClient).when(blobServiceClient).getBlobContainerClient(anyString());
            storageService = new AzureBlobUserStorageService(
                    "client",
                    "secret",
                    "endpoint",
                    "container",
                    "app",
                    encryptor,
                    objectMapperBuilder
                    );


            Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        }
    }

    @Test
    void testRetrieveKey(){
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        Mockito.doReturn(new byte[]{
                'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'
        }).when(mockData).toBytes();

        String result = this.storageService.retrieveKey("some Key");

        Assertions.assertEquals("Hello World!", result);
    }

    @SneakyThrows
    @Test
    void testRetrieveUser() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn(ObjectTestProvider.convertObjects(user, mapper))
                .when(mockData).toBytes();

        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(TcUser.class));

        Mockito.doReturn(true).when(client).exists();
        TcUser returnedUser = this.storageService.retrieveUser("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(user, returnedUser);

        Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        Mockito.doReturn(false).when(client).exists();
        returnedUser = this.storageService.retrieveUser("id");
        Assertions.assertNull(returnedUser);
    }

    @SneakyThrows
    @Test
    void testGetAccountById() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn(user)
                .when(mockData).toObject(TcUser.class);

        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(TcUser.class));

        Mockito.doReturn(true).when(client).exists();
        Optional<TcUser> returnedUser = this.storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isPresent());
        Assertions.assertEquals(user, returnedUser.get());

        Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        Mockito.doReturn(false).when(client).exists();
        returnedUser = this.storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isEmpty());
    }

    @SneakyThrows
    @Test
    void testRetrieveBrand() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        TcBrands brand = ObjectTestProvider.getBrand();

        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper))
                .when(mockData).toBytes();

        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(TcBrands.class));

        Mockito.doReturn(true).when(client).exists();
        TcBrands returnedUser = this.storageService.retrieveBrand("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        Mockito.doReturn(false).when(client).exists();
        returnedUser = this.storageService.retrieveBrand("id");
        Assertions.assertNull(returnedUser);
    }

    @SneakyThrows
    @Test
    void testGetBrandById() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        TcBrands brand = ObjectTestProvider.getBrand();

        Mockito.doReturn(brand)
                .when(mockData).toObject(TcBrands.class);

        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(TcBrands.class));

        //Mockito.doReturn(true).when(client).exists();
        Optional<TcBrands> returnedUser = this.storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isPresent());
        Assertions.assertEquals(brand, returnedUser.get());

        Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        Mockito.doThrow(RuntimeException.class).when(client).downloadContent();
        returnedUser = this.storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isEmpty());
    }

    @SneakyThrows
    @Test
    void testRetrieveAppLocker() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        AppLocker brand = new AppLocker();

        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper))
                .when(mockData).toBytes();

        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(AppLocker.class));

        //Mockito.doReturn(true).when(client).exists();
        AppLocker returnedUser = this.storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        Mockito.doThrow(RuntimeException.class).when(client).downloadContent();
        returnedUser = this.storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);
    }

    @SneakyThrows
    @Test
    void testRetrieveSessionList() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(mockData).when(client).downloadContent();

        SessionListV2 sessionList = new SessionListV2();

        Mockito.doReturn(ObjectTestProvider.convertObjects(sessionList, mapper))
                .when(mockData).toBytes();

        Mockito.doReturn(sessionList).when(encryptor).decrypt(Mockito.any(SessionListV2.class));

        //Mockito.doReturn(true).when(client).exists();
        SessionListV2 returnedUser = this.storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(sessionList, returnedUser);

        Mockito.doReturn(client).when(containerClient).getBlobClient(anyString());
        Mockito.doThrow(RuntimeException.class).when(client).downloadContent();
        returnedUser = this.storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedUser);
    }


    @Test
    void testSaveUser(){
        TcUser user = ObjectTestProvider.getTcUser();
        Mockito.doReturn(user).when(encryptor).encrypt(user);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(user).when(mockData).toObject(TcUser.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(TcUser.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                TcUser locker = data.toObject(TcUser.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(user, locker);
                return null;
            }).when(client).upload(mockData, true);

            this.storageService.saveUser(user);
        }
    }

    @Test
    void testSaveLogins(){
        AppLocker brand = new AppLocker();
        Mockito.doReturn(brand).when(encryptor).encrypt(brand);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(brand).when(mockData).toObject(AppLocker.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(AppLocker.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                AppLocker locker = data.toObject(AppLocker.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(brand, locker);
                return null;
            }).when(client).upload(mockData, true);

            this.storageService.saveLogins(brand, "id");
        }
    }

    @Test
    void testSaveBrand(){
        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(brand).when(encryptor).encrypt(brand);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(brand).when(mockData).toObject(TcBrands.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(TcBrands.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                TcBrands locker = data.toObject(TcBrands.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(brand, locker);
                return null;
            }).when(client).upload(mockData, true);

            this.storageService.saveBrand(brand);
        }
    }

    @Test
    void testSaveSessions(){
        SessionListV2 sessionList = new SessionListV2();
        Mockito.doReturn(sessionList).when(encryptor).encrypt(sessionList);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(sessionList).when(mockData).toObject(SessionListV2.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(SessionListV2.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                SessionListV2 locker = data.toObject(SessionListV2.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(sessionList, locker);
                return null;
            }).when(client).upload(mockData, true);

            this.storageService.saveSessions(sessionList, "id");
        }
    }
}
