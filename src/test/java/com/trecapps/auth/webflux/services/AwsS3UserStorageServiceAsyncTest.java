package com.trecapps.auth.webflux.services;

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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.BytesWrapper;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.internal.async.ByteBuffersAsyncRequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClientBuilder;
import software.amazon.awssdk.services.s3.model.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
public class AwsS3UserStorageServiceAsyncTest {

    @Mock
    S3AsyncClient client;
    @Mock
    IFieldEncryptor encryptor;

    ObjectMapper mapper;

    AwsS3UserStorageServiceAsync storageService;


    @BeforeEach
    void setUp(){
        Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();

        mapper = objectMapperBuilder.createXmlMapper(false).build();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        try(MockedStatic<S3AsyncClient> mockedStatic = Mockito.mockStatic(S3AsyncClient.class))
        {
            S3AsyncClientBuilder builder = Mockito.mock(S3AsyncClientBuilder.class);
            mockedStatic.when(S3AsyncClient::builder).thenReturn(builder);

            Mockito.doReturn(builder).when(builder).credentialsProvider(Mockito.any(AwsCredentialsProvider.class));
            Mockito.doReturn(builder).when(builder).region(Mockito.any(Region.class));
            Mockito.doReturn(client).when(builder).build();

            storageService = new AwsS3UserStorageServiceAsync(
                    "client",
                    "secret",
                    "us-east-1",
                    "bucket",
                    "app",
                    encryptor,
                    objectMapperBuilder);

        }
    }

    @Test
    void testRetrieveKey() throws IOException {
        ResponseBytes bytesResponse = Mockito.mock(ResponseBytes.class);

        Mockito.doReturn("Hello World!").when(bytesResponse).asUtf8String();

        CompletableFuture<BytesWrapper> future = CompletableFuture.supplyAsync(()-> bytesResponse);

        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));

        Mono<String> mono = this.storageService.retrieveKey("some Key");

        StepVerifier.create(mono).consumeNextWith((String result) -> {
            Assertions.assertEquals("Hello World!", result);
        }).verifyComplete();
    }

    @SneakyThrows
    @Test
    void testGetAccountById() {
        TcUser user = ObjectTestProvider.getTcUser();
        Mockito.doReturn(user).when(encryptor).decrypt(any(TcUser.class));
        ResponseBytes bytesResponse = Mockito.mock(ResponseBytes.class);

        Mockito.doReturn(mapper.writeValueAsString(user)).when(bytesResponse).asUtf8String();
        CompletableFuture<BytesWrapper> future = CompletableFuture.supplyAsync(()-> bytesResponse);
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));

        Mono<Optional<TcUser>> mono = this.storageService.getAccountById("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TcUser> returnedUser) -> {
                    Assertions.assertTrue(returnedUser.isPresent());
                    Assertions.assertEquals(user, returnedUser.get());
                })
                .verifyComplete();

        future = CompletableFuture.failedFuture(NoSuchKeyException.builder().build());
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));
        mono = this.storageService.getAccountById("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TcUser> returnedUser) -> {
                    Assertions.assertTrue(returnedUser.isEmpty());
                })
                .verifyComplete();
    }

    @SneakyThrows
    @Test
    void testGetBrandById() {
        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(TcBrands.class));
        ResponseBytes bytesResponse = Mockito.mock(ResponseBytes.class);

        Mockito.doReturn(mapper.writeValueAsString(brand)).when(bytesResponse).asUtf8String();
        CompletableFuture<BytesWrapper> future = CompletableFuture.supplyAsync(()-> bytesResponse);
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));

        Mono<Optional<TcBrands>> mono = this.storageService.getBrandById("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TcBrands> returnedUser) -> {
                    Assertions.assertTrue(returnedUser.isPresent());
                    Assertions.assertEquals(brand, returnedUser.get());
                })
                .verifyComplete();

        future = CompletableFuture.failedFuture(NoSuchKeyException.builder().build());
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));
        mono = this.storageService.getBrandById("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TcBrands> returnedUser) -> {
                    Assertions.assertTrue(returnedUser.isEmpty());
                })
                .verifyComplete();
    }



    @SneakyThrows
    @Test
    void testRetrieveAppLocker() {
        AppLocker brand = new AppLocker();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(AppLocker.class));
        ResponseBytes bytesResponse = Mockito.mock(ResponseBytes.class);

        Mockito.doReturn(mapper.writeValueAsString(brand)).when(bytesResponse).asUtf8String();
        CompletableFuture<BytesWrapper> future = CompletableFuture.supplyAsync(()-> bytesResponse);
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));

        Mono<Optional<AppLocker>> mono = this.storageService.retrieveAppLocker("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<AppLocker> returnedUser) -> {
                    Assertions.assertTrue(returnedUser.isPresent());
                    Assertions.assertEquals(brand, returnedUser.get());
                })
                .verifyComplete();

        future = CompletableFuture.failedFuture(NoSuchKeyException.builder().build());
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));
        mono = this.storageService.retrieveAppLocker("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<AppLocker> returnedUser) -> {
                    Assertions.assertTrue(returnedUser.isPresent());
                })
                .verifyComplete();
    }

    @SneakyThrows
    @Test
    void testRetrieveSessionList() {
        SessionListV2 brand = new SessionListV2();
        Mockito.doReturn(brand).when(encryptor).decrypt(any(SessionListV2.class));
        ResponseBytes bytesResponse = Mockito.mock(ResponseBytes.class);

        Mockito.doReturn(mapper.writeValueAsString(brand)).when(bytesResponse).asUtf8String();
        CompletableFuture<BytesWrapper> future = CompletableFuture.supplyAsync(()-> bytesResponse);
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));

        Mono<SessionListV2> mono = this.storageService.retrieveSessionList("some Key");
        StepVerifier.create(mono)
                .consumeNextWith((SessionListV2 returnedUser) -> {
                    Assertions.assertNotNull(returnedUser);
                    Assertions.assertEquals(brand, returnedUser);
                })
                .verifyComplete();

        future = CompletableFuture.failedFuture(NoSuchKeyException.builder().build());
        Mockito.doReturn( future).when(client)
                .getObject(Mockito.any(GetObjectRequest.class), Mockito.any(AsyncResponseTransformer.class));
        mono = this.storageService.retrieveSessionList("some Key");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertNotNull)
                .verifyComplete();
    }

    @Test
    void testSaveLoginsMono(){
        AppLocker brand = new AppLocker();
        Mockito.doReturn(brand).when(encryptor).encrypt(brand);

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ByteBuffersAsyncRequestBody body = invoke.getArgument(1, ByteBuffersAsyncRequestBody.class);
            body.subscribe((ByteBuffer buffer) -> {
                try {
                    byte[] bytes = new byte[buffer.limit()];
                    buffer.get(bytes);
                    AppLocker locker =mapper.readValue(bytes, AppLocker.class);
                    Assertions.assertNotNull(locker);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).join();
            return CompletableFuture.supplyAsync(() -> Mockito.mock(PutObjectResponse.class));
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(AsyncRequestBody.class));

        Mono<Void> mono = storageService.saveLoginsMono(brand, "id");
        StepVerifier.create(mono).verifyComplete();
    }

    @Test
    void testSaveUserMono(){
        TcUser brand = ObjectTestProvider.getTcUser();
        Mockito.doReturn(brand).when(encryptor).encrypt(brand);

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ByteBuffersAsyncRequestBody body = invoke.getArgument(1, ByteBuffersAsyncRequestBody.class);
            body.subscribe((ByteBuffer buffer) -> {
                try {
                    byte[] bytes = new byte[buffer.limit()];
                    buffer.get(bytes);
                    TcUser locker = mapper.readValue(bytes, TcUser.class);
                    Assertions.assertNotNull(locker);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).join();
            return CompletableFuture.supplyAsync(() -> Mockito.mock(PutObjectResponse.class));
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(AsyncRequestBody.class));

        Mono<Void> mono = storageService.saveUserMono(brand);
        StepVerifier.create(mono).verifyComplete();
    }

    @Test
    void testSaveBrandMono(){
        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(brand).when(encryptor).encrypt(brand);

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ByteBuffersAsyncRequestBody body = invoke.getArgument(1, ByteBuffersAsyncRequestBody.class);
            body.subscribe((ByteBuffer buffer) -> {
                try {
                    byte[] bytes = new byte[buffer.limit()];
                    buffer.get(bytes);
                    TcBrands locker =mapper.readValue(bytes, TcBrands.class);
                    Assertions.assertNotNull(locker);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).join();
            return CompletableFuture.supplyAsync(() -> Mockito.mock(PutObjectResponse.class));
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(AsyncRequestBody.class));

        Mono<Void> mono = storageService.saveBrandMono(brand);
        StepVerifier.create(mono).verifyComplete();
    }

    @Test
    void testSaveSessionsMono(){
        SessionListV2 brand = new SessionListV2();
        Mockito.doReturn(brand).when(encryptor).encrypt(brand);

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ByteBuffersAsyncRequestBody body = invoke.getArgument(1, ByteBuffersAsyncRequestBody.class);
            body.subscribe((ByteBuffer buffer) -> {
                try {
                    byte[] bytes = new byte[buffer.limit()];
                    buffer.get(bytes);
                    SessionListV2 locker =mapper.readValue(bytes, SessionListV2.class);
                    Assertions.assertNotNull(locker);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).join();
            return CompletableFuture.supplyAsync(() -> Mockito.mock(PutObjectResponse.class));
        }).when(client).putObject(Mockito.any(PutObjectRequest.class), Mockito.any(AsyncRequestBody.class));

        Mono<Void> mono = storageService.saveSessionsMono(brand, "id");
        StepVerifier.create(mono).verifyComplete();
    }
}
