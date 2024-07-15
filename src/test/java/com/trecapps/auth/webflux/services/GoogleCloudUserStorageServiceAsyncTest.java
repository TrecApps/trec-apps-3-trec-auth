package com.trecapps.auth.webflux.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.cloud.storage.*;
import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.TcBrands;
import com.trecapps.auth.common.models.TcUser;

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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class GoogleCloudUserStorageServiceAsyncTest {

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

    GoogleCloudUserStorageServiceAsync storageService;



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

            storageService = new GoogleCloudUserStorageServiceAsync(
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
        Mono<String> mono = this.storageService.retrieveKey("some Key");

        StepVerifier.create(mono)
                        .consumeNextWith((String result) -> {
                            Assertions.assertEquals("Hello World!", result);
                        }).verifyComplete();
    }

    @Test
    void testGetAccountByIdSuccess(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        TcUser user = ObjectTestProvider.getTcUser();
        Mockito.doReturn(ObjectTestProvider.convertObjects(user, mapper)).when(object).getContent();
        Mockito.doReturn(user).when(encryptor).decrypt(any(TcUser.class));

        Mockito.doReturn(true).when(object).exists();
        Mono<Optional<TcUser>> mono = storageService.getAccountById("id");

        StepVerifier.create(mono).consumeNextWith((Optional<TcUser> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
            Assertions.assertEquals(user, returnedUser.get());
        }).verifyComplete();
    }

    @Test
    void testGetAccountByIdFalseExists(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());
        Mockito.doReturn(false).when(object).exists();
        Mono<Optional<TcUser>> mono = storageService.getAccountById("id");
        StepVerifier.create(mono).consumeNextWith((Optional<TcUser> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isEmpty());
        }).verifyComplete();
    }

    @Test
    void testGetAccountByIdNull(){
        Mono<Optional<TcUser>> mono = storageService.getAccountById("id");
        StepVerifier.create(mono).consumeNextWith((Optional<TcUser> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isEmpty());
        }).verifyComplete();
    }


    @Test
    void testGetBrandByIdSuccess(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(TcBrands.class));

        Mockito.doReturn(true).when(object).exists();
        Mono<Optional<TcBrands>> mono = storageService.getBrandById("id");

        StepVerifier.create(mono).consumeNextWith((Optional<TcBrands> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
            Assertions.assertEquals(brand, returnedUser.get());
        }).verifyComplete();
    }

    @Test
    void testGetBrandByIdFalseExists(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());
        Mockito.doReturn(false).when(object).exists();
        Mono<Optional<TcBrands>> mono = storageService.getBrandById("id");
        StepVerifier.create(mono).consumeNextWith((Optional<TcBrands> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isEmpty());
        }).verifyComplete();
    }

    @Test
    void testGetBrandByIdNull(){
        Mono<Optional<TcBrands>> mono = storageService.getBrandById("id");
        StepVerifier.create(mono).consumeNextWith((Optional<TcBrands> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isEmpty());
        }).verifyComplete();
    }

    @Test
    void testRetrieveAppLockerSuccess(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        AppLocker brand = new AppLocker();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(AppLocker.class));

        Mockito.doReturn(true).when(object).exists();
        Mono<Optional<AppLocker>> mono = storageService.retrieveAppLocker("id");

        StepVerifier.create(mono).consumeNextWith((Optional<AppLocker> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
            Assertions.assertEquals(brand, returnedUser.get());
        }).verifyComplete();
    }

    @Test
    void testRetrieveAppLocketFalseExists(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());
        Mockito.doReturn(false).when(object).exists();
        Mono<Optional<AppLocker>> mono = storageService.retrieveAppLocker("id");
        StepVerifier.create(mono).consumeNextWith((Optional<AppLocker> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
        }).verifyComplete();
    }

    @Test
    void testRetrieveAppLockerNull(){
        Mono<Optional<AppLocker>> mono = storageService.retrieveAppLocker("id");
        StepVerifier.create(mono).consumeNextWith((Optional<AppLocker> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
        }).verifyComplete();
    }

    @Test
    void testRetrieveSessionListSuccess(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());

        SessionListV2 brand = new SessionListV2();
        Mockito.doReturn(ObjectTestProvider.convertObjects(brand, mapper)).when(object).getContent();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(SessionListV2.class));

        Mockito.doReturn(true).when(object).exists();
        Mono<SessionListV2> mono = storageService.retrieveSessionList("id");

        StepVerifier.create(mono).consumeNextWith((SessionListV2 returnedUser) -> {
            Assertions.assertNotNull(returnedUser);
            Assertions.assertEquals(brand, returnedUser);
        }).verifyComplete();
    }

    @Test
    void testRetrieveSessionListFalseExists(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.doReturn(object).when(client).get(anyString());
        Mockito.doReturn(false).when(object).exists();
        Mono<SessionListV2> mono = storageService.retrieveSessionList("id");
        StepVerifier.create(mono).consumeNextWith(Assertions::assertNotNull).verifyComplete();
    }

    @Test
    void testRetrieveSessionListNull(){
        Mono<SessionListV2> mono = storageService.retrieveSessionList("id");
        StepVerifier.create(mono).consumeNextWith(Assertions::assertNotNull).verifyComplete();
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

        Mono<Void> mono = storageService.saveLoginsMono(locker, "id");

        StepVerifier.create(mono).verifyComplete();

        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        mono = storageService.saveLoginsMono(locker, "id");
        StepVerifier.create(mono).verifyComplete();
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

        Mono<Void> mono = storageService.saveUserMono(user);
        StepVerifier.create(mono).verifyComplete();
        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        mono = storageService.saveUserMono(user);
        StepVerifier.create(mono).verifyComplete();
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

        Mono<Void> mono = storageService.saveBrandMono(brand);
        StepVerifier.create(mono).verifyComplete();
        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        mono = storageService.saveBrandMono(brand);
        StepVerifier.create(mono).verifyComplete();
    }

    @Test
    void testSaveSessions(){
        Blob object = Mockito.mock(Blob.class);
        Mockito.lenient().doReturn(object).when(storage).get(anyString(), anyString());
        Mockito.lenient().doReturn(1L).when(object).getGeneration();
        Mockito.lenient().doReturn("bucket").when(client).getName();


        SessionListV2 brand = new SessionListV2();
        Mockito.doReturn(brand).when(encryptor).encrypt(any(SessionListV2.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {

            byte[] data = invoke.getArgument(1, byte[].class);
            SessionListV2 locker1 = mapper.readValue(data, SessionListV2.class);
            Assertions.assertNotNull(brand);
            Assertions.assertEquals(brand, locker1);
            return null;

        }).when(storage).create(any(BlobInfo.class), any(byte[].class), any(Storage.BlobTargetOption.class));

        Mono<Void> mono = storageService.saveSessionsMono(brand, "id");
        StepVerifier.create(mono).verifyComplete();
        Mockito.doReturn(null).when(storage).get(anyString(), anyString());
        mono = storageService.saveSessionsMono(brand, "id");
        StepVerifier.create(mono).verifyComplete();
    }

}
