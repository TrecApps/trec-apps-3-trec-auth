package com.trecapps.auth.web.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.cloud.storage.*;
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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class GoogleCloudUserStorageServiceTest {

    @Mock
    IFieldEncryptor encryptor;

    ObjectMapper mapper;

    @Mock
    StorageOptions.Builder mockOptions;
    @Mock
    StorageOptions options;

    @Mock
    Bucket client;
    @Mock
    Storage storage;

    GoogleCloudUserStorageService storageService;



    @BeforeEach
    void setUp(){
        Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();

        mapper = objectMapperBuilder.createXmlMapper(false).build();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        try(MockedStatic<StorageOptions> mockedStatic = Mockito.mockStatic(StorageOptions.class)){
            mockedStatic.when(StorageOptions::newBuilder).thenReturn(mockOptions);
            Mockito.doReturn(mockOptions).when(mockOptions).setProjectId(anyString());
            Mockito.doReturn(options).when(mockOptions).build();
            Mockito.doReturn(storage).when(options).getService();
            Mockito.doReturn(client).when(storage).get(anyString());

            storageService = new GoogleCloudUserStorageService(
                    "Project",
                    "bucket",
                    "app",
                    encryptor,
                    objectMapperBuilder
            );
        }
    }


    @Test
    void testRetrieveKey(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        Mockito.doReturn(new byte[]{
                'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'
        }).when(object).getContent();

        //Mockito.doReturn(true).when(object).exists();
        String result = this.storageService.retrieveKey("some Key");

        Assertions.assertEquals("Hello World!", result);
    }

    @SneakyThrows
    @Test
    void testRetrieveUser(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        TcUser user = ObjectTestProvider.getTcUser();
        Mockito.doReturn(ObjectTestProvider.convertObjects(user, mapper)).when(object).getContent();
        Mockito.doReturn(user).when(encryptor).decrypt(any(TcUser.class));

        Mockito.doReturn(true).when(object).exists();
        TcUser returnedUser = storageService.retrieveUser("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(user, returnedUser);

        Mockito.doReturn(false).when(object).exists();
        returnedUser = this.storageService.retrieveUser("id");
        Assertions.assertNull(returnedUser);

        Mockito.doReturn(null).when(client).get(anyString());
        returnedUser = this.storageService.retrieveUser("id");
        Assertions.assertNull(returnedUser);
    }

    @Test
    void testGetAccountById(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        TcUser user = ObjectTestProvider.getTcUser();
        Mockito.doReturn(ObjectTestProvider.convertObjects(user, mapper)).when(object).getContent();
        Mockito.doReturn(user).when(encryptor).decrypt(any(TcUser.class));

        Mockito.doReturn(true).when(object).exists();
        Optional<TcUser> returnedUser = storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isPresent());
        Assertions.assertEquals(user, returnedUser.get());

        Mockito.doReturn(false).when(object).exists();
        returnedUser = this.storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isEmpty());

        Mockito.doReturn(null).when(client).get(anyString());
        returnedUser = this.storageService.getAccountById("id");
        Assertions.assertTrue(returnedUser.isEmpty());
    }

    @SneakyThrows
    @Test
    void testRetrieveBrand(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(TcBrands.class));

        Mockito.doReturn(true).when(object).exists();
        TcBrands returnedUser = storageService.retrieveBrand("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doReturn(false).when(object).exists();
        returnedUser = this.storageService.retrieveBrand("id");
        Assertions.assertNull(returnedUser);

        Mockito.doReturn(null).when(client).get(anyString());
        returnedUser = this.storageService.retrieveBrand("id");
        Assertions.assertNull(returnedUser);
    }

    @Test
    void testGetBrandById(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(TcBrands.class));

        Mockito.doReturn(true).when(object).exists();
        Optional<TcBrands> returnedUser = storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isPresent());
        Assertions.assertEquals(brand, returnedUser.get());

        Mockito.doReturn(false).when(object).exists();
        returnedUser = this.storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isEmpty());

        Mockito.doReturn(null).when(client).get(anyString());
        returnedUser = this.storageService.getBrandById("id");
        Assertions.assertTrue(returnedUser.isEmpty());
    }

    @SneakyThrows
    @Test
    void testRetrieveAppLocker(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        AppLocker brand = new AppLocker();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(AppLocker.class));

        Mockito.doReturn(true).when(object).exists();
        AppLocker returnedUser = storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doReturn(false).when(object).exists();
        returnedUser = this.storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);

        Mockito.doReturn(null).when(client).get(anyString());
        returnedUser = this.storageService.retrieveAppLocker("id");
        Assertions.assertNotNull(returnedUser);
    }

    @SneakyThrows
    @Test
    void testRetrieveSessionList(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        SessionListV2 brand = new SessionListV2();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(SessionListV2.class));

        Mockito.doReturn(true).when(object).exists();
        SessionListV2 returnedUser = storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedUser);
        Assertions.assertEquals(brand, returnedUser);

        Mockito.doReturn(false).when(object).exists();
        returnedUser = this.storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedUser);

        Mockito.doReturn(null).when(client).get(anyString());
        returnedUser = this.storageService.retrieveSessionList("id");
        Assertions.assertNotNull(returnedUser);
    }

    @Test
    void testSaveLogins(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.lenient().doReturn(object).when(storage).get(anyString(), anyString());
        Mockito.lenient().doReturn(1L).when(object).getGeneration();
        Mockito.lenient().doReturn("bucket").when(client).getName();

        AppLocker locker = new AppLocker();
        Mockito.doReturn(locker).when(encryptor).encrypt(any(AppLocker.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {

            byte[] data = invoke.getArgument(1, byte[].class);
            AppLocker locker1 = mapper.readValue(data, AppLocker.class);
            Assertions.assertNotNull(locker);
            Assertions.assertEquals(locker, locker1);
            return null;

        }).when(storage).create(any(BlobInfo.class), any(byte[].class), any(Storage.BlobTargetOption.class));

        storageService.saveLogins(locker, "id");

        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        storageService.saveLogins(locker, "id");
    }

    @Test
    void testSaveUser(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.lenient().doReturn(object).when(storage).get(anyString(), anyString());
        Mockito.lenient().doReturn(1L).when(object).getGeneration();
        Mockito.lenient().doReturn("bucket").when(client).getName();

        TcUser user = ObjectTestProvider.getTcUser();
        Mockito.doReturn(user).when(encryptor).encrypt(any(TcUser.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {

            byte[] data = invoke.getArgument(1, byte[].class);
            TcUser locker1 = mapper.readValue(data, TcUser.class);
            Assertions.assertNotNull(user);
            Assertions.assertEquals(user, locker1);
            return null;

        }).when(storage).create(any(BlobInfo.class), any(byte[].class), any(Storage.BlobTargetOption.class));

        storageService.saveUser(user);

        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        storageService.saveUser(user);
    }

    @Test
    void testSaveSessions(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.lenient().doReturn(object).when(storage).get(anyString(), anyString());
        Mockito.lenient().doReturn(1L).when(object).getGeneration();
        Mockito.lenient().doReturn("bucket").when(client).getName();

        SessionListV2 sessionList = new SessionListV2();
        Mockito.doReturn(sessionList).when(encryptor).encrypt(any(SessionListV2.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {

            byte[] data = invoke.getArgument(1, byte[].class);
            SessionListV2 locker1 = mapper.readValue(data, SessionListV2.class);
            Assertions.assertNotNull(sessionList);
            Assertions.assertEquals(sessionList, locker1);
            return null;

        }).when(storage).create(any(BlobInfo.class), any(byte[].class), any(Storage.BlobTargetOption.class));

        storageService.saveSessions(sessionList, "id");

        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        storageService.saveSessions(sessionList, "id");
    }

    @Test
    void testSaveBrand(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.lenient().doReturn(object).when(storage).get(anyString(), anyString());
        Mockito.lenient().doReturn(1L).when(object).getGeneration();
        Mockito.lenient().doReturn("bucket").when(client).getName();

        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(brand).when(encryptor).encrypt(any(TcBrands.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {

            byte[] data = invoke.getArgument(1, byte[].class);
            TcBrands locker1 = mapper.readValue(data, TcBrands.class);
            Assertions.assertNotNull(brand);
            Assertions.assertEquals(brand, locker1);
            return null;

        }).when(storage).create(any(BlobInfo.class), any(byte[].class), any(Storage.BlobTargetOption.class));

        storageService.saveBrand(brand);

        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        storageService.saveBrand(brand);
    }
}
