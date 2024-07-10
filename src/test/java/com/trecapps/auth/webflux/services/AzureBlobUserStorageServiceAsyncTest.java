package com.trecapps.auth.webflux.services;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.util.BinaryData;
import com.azure.storage.blob.BlobAsyncClient;
import com.azure.storage.blob.BlobContainerAsyncClient;
import com.azure.storage.blob.BlobServiceAsyncClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlockBlobItem;
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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
public class AzureBlobUserStorageServiceAsyncTest {
    ObjectMapper mapper;
    @Mock
    IFieldEncryptor encryptor;
    @Mock
    BlobServiceAsyncClient client;
    @Mock
    BlobContainerAsyncClient containerClient;
    @Mock
    BlobAsyncClient asyncClient;

    AzureBlobUserStorageServiceAsync storageService;

    @BeforeEach
    void setUp() {
        Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();

        mapper = objectMapperBuilder.createXmlMapper(false).build();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        try(MockedConstruction<BlobServiceClientBuilder> construction =
                    Mockito.mockConstruction(BlobServiceClientBuilder.class, (mock, context)-> {
                        doReturn(mock).when(mock).credential(any(AzureNamedKeyCredential.class));
                        doReturn(mock).when(mock).endpoint(anyString());
                        doReturn(client).when(mock).buildAsyncClient();
                    })) {
            Mockito.doReturn(containerClient).when(client).getBlobContainerAsyncClient(anyString());
            storageService = new AzureBlobUserStorageServiceAsync(
                    "client",
                    "secret",
                    "endpoint",
                    "container",
                    "app",
                    encryptor,
                    objectMapperBuilder
            );
        }
        Mockito.doReturn(asyncClient).when(containerClient).getBlobAsyncClient(anyString());

    }

    @Test
    void testRetrieveKey(){
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(Mono.just(mockData)).when(asyncClient).downloadContent();

        Mockito.doReturn(new byte[]{
                'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'
        }).when(mockData).toBytes();

        Mono<String> mono = this.storageService.retrieveKey("some Key");
        StepVerifier.create(mono).consumeNextWith((String result) -> {
            Assertions.assertEquals("Hello World!", result);
        }).verifyComplete();

    }

    @SneakyThrows
    @Test
    void testGetAccountById() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(Mono.just(mockData)).when(asyncClient).downloadContent();

        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn(user, mapper)
                .when(mockData).toObject(TcUser.class);

        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(TcUser.class));


        Mono<Optional<TcUser>> mono = this.storageService.getAccountById("id");

        StepVerifier.create(mono).consumeNextWith((Optional<TcUser> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
            Assertions.assertEquals(user, returnedUser.get());
        }).verifyComplete();

        doReturn(Mono.error(new RuntimeException())).when(asyncClient).downloadContent();

        mono = this.storageService.getAccountById("id");

        StepVerifier.create(mono).consumeNextWith((Optional<TcUser> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isEmpty());
        }).verifyComplete();

    }

    @Test
    void testGetBrandById() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(Mono.just(mockData)).when(asyncClient).downloadContent();

        TcBrands brand = ObjectTestProvider.getBrand();

        Mockito.doReturn(brand, mapper)
                .when(mockData).toObject(TcBrands.class);

        Mockito.doReturn(brand).when(encryptor).decrypt(Mockito.any(TcBrands.class));


        Mono<Optional<TcBrands>> mono = this.storageService.getBrandById("id");

        StepVerifier.create(mono).consumeNextWith((Optional<TcBrands> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
            Assertions.assertEquals(brand, returnedUser.get());
        }).verifyComplete();

        doReturn(Mono.error(new RuntimeException())).when(asyncClient).downloadContent();

        mono = this.storageService.getBrandById("id");

        StepVerifier.create(mono).consumeNextWith((Optional<TcBrands> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isEmpty());
        }).verifyComplete();

    }

    @Test
    void testRetrieveAppLocker() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(Mono.just(mockData)).when(asyncClient).downloadContent();

        AppLocker user = new AppLocker();

        Mockito.doReturn(user, mapper)
                .when(mockData).toObject(AppLocker.class);

        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(AppLocker.class));


        Mono<Optional<AppLocker>> mono = this.storageService.retrieveAppLocker("id");

        StepVerifier.create(mono).consumeNextWith((Optional<AppLocker> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
            Assertions.assertEquals(user, returnedUser.get());
        }).verifyComplete();

        doReturn(Mono.error(new RuntimeException())).when(asyncClient).downloadContent();

        mono = this.storageService.retrieveAppLocker("id");

        StepVerifier.create(mono).consumeNextWith((Optional<AppLocker> returnedUser) -> {
            Assertions.assertTrue(returnedUser.isPresent());
        }).verifyComplete();

    }

    @Test
    void testRetrieveSessionList() {
        BinaryData mockData= Mockito.mock(BinaryData.class);
        doReturn(Mono.just(mockData)).when(asyncClient).downloadContent();

        SessionListV2 user = new SessionListV2();

        Mockito.doReturn(user, mapper)
                .when(mockData).toObject(TcUser.class);

        Mockito.doReturn(user).when(encryptor).decrypt(Mockito.any(TcUser.class));


        Mono<SessionListV2> mono = this.storageService.retrieveSessionList("id");

        StepVerifier.create(mono).consumeNextWith((SessionListV2 returnedUser) -> {
            Assertions.assertNotNull(returnedUser);
            Assertions.assertEquals(user, returnedUser);
        }).verifyComplete();

        doReturn(Mono.error(new RuntimeException())).when(asyncClient).downloadContent();

        mono = this.storageService.retrieveSessionList("id");

        StepVerifier.create(mono).consumeNextWith(Assertions::assertNotNull).verifyComplete();

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
                return Mono.just(Mockito.mock(BlockBlobItem.class));
            }).when(asyncClient).upload(mockData, true);

            Mono<Void> mono = this.storageService.saveUserMono(user);
            StepVerifier.create(mono).verifyComplete();
        }
    }

    @Test
    void testBrandUser(){
        TcBrands user = ObjectTestProvider.getBrand();
        Mockito.doReturn(user).when(encryptor).encrypt(user);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(user).when(mockData).toObject(TcBrands.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(TcBrands.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                TcBrands locker = data.toObject(TcBrands.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(user, locker);
                return Mono.just(Mockito.mock(BlockBlobItem.class));
            }).when(asyncClient).upload(mockData, true);

            Mono<Void> mono = this.storageService.saveBrandMono(user);
            StepVerifier.create(mono).verifyComplete();
        }
    }

    @Test
    void testSaveAppLocker(){
        AppLocker user = new AppLocker();
        Mockito.doReturn(user).when(encryptor).encrypt(user);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(user).when(mockData).toObject(AppLocker.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(AppLocker.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                AppLocker locker = data.toObject(AppLocker.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(user, locker);
                return Mono.just(Mockito.mock(BlockBlobItem.class));
            }).when(asyncClient).upload(mockData, true);

            Mono<Void> mono = this.storageService.saveLoginsMono(user, "id");
            StepVerifier.create(mono).verifyComplete();
        }
    }

    @Test
    void testSaveSessions(){
        SessionListV2 user = new SessionListV2();
        Mockito.doReturn(user).when(encryptor).encrypt(user);
        BinaryData mockData= Mockito.mock(BinaryData.class);
        Mockito.doReturn(user).when(mockData).toObject(SessionListV2.class);

        try(MockedStatic<BinaryData> binaryStatic = Mockito.mockStatic(BinaryData.class)){
            binaryStatic.when(() -> BinaryData.fromObject(any(SessionListV2.class))).thenReturn(mockData);
            Mockito.doAnswer((InvocationOnMock invoke) -> {
                BinaryData data = invoke.getArgument(0, BinaryData.class);
                SessionListV2 locker = data.toObject(SessionListV2.class);
                Assertions.assertNotNull(locker);
                Assertions.assertEquals(user, locker);
                return Mono.just(Mockito.mock(BlockBlobItem.class));
            }).when(asyncClient).upload(mockData, true);

            Mono<Void> mono = this.storageService.saveSessionsMono(user, "id");
            StepVerifier.create(mono).verifyComplete();
        }
    }
}
