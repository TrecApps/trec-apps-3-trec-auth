package com.trecapps.auth.webflux.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.encryptors.IFieldEncryptor;
import lombok.SneakyThrows;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.BytesWrapper;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class AwsS3UserStorageServiceAsync implements IUserStorageServiceAsync {


    S3AsyncClient client;
    ObjectMapper objectMapper;
    String app;

    String s3BucketName;

    IFieldEncryptor encryptor;

    AwsS3UserStorageServiceAsync(String clientName,
                            String clientSecret,
                            String s3Region,
                            String s3BucketName,
                            String app,
                            IFieldEncryptor encryptor1,
                            Jackson2ObjectMapperBuilder objectMapperBuilder){
        AwsBasicCredentials awsBasicCredentials = AwsBasicCredentials.create(clientName, clientSecret);
        StaticCredentialsProvider staticCredentialsProvider = StaticCredentialsProvider.create(awsBasicCredentials);
                client = S3AsyncClient.builder()
                        .credentialsProvider(staticCredentialsProvider)
                        .region(Region.of(s3Region)).build();

        setUp(s3BucketName, app, encryptor1, objectMapperBuilder);
    }

    AwsS3UserStorageServiceAsync(
                            String s3Region,
                            String s3BucketName,
                            String app,
                            IFieldEncryptor encryptor1,
                            Jackson2ObjectMapperBuilder objectMapperBuilder){
        client = S3AsyncClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(Region.of(s3Region)).build();

        setUp(s3BucketName, app, encryptor1, objectMapperBuilder);
    }

    void setUp(String s3BucketName,
               String app,
               IFieldEncryptor encryptor1,
               Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.s3BucketName = s3BucketName;
        this.encryptor = encryptor1;
    }

    @Override
    public Mono<String> retrieveKey(String keyId) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key(keyId)
                .build();

        return Mono.fromFuture(client.getObject(request, AsyncResponseTransformer.toBytes()))
                .map(BytesWrapper::asUtf8String);
    }


    @SneakyThrows
    <T> T getContent(String content, Class<T> type){
        return objectMapper.readValue(content, type);
    }

    @SneakyThrows
    @Override
    public Mono<Optional<TcUser>> getAccountById(String id) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("user-" + id)
                .build();

        return Mono.fromFuture(client.getObject(request, AsyncResponseTransformer.toBytes()))
                .map(BytesWrapper::asUtf8String)
                .map((String content) ->getContent(content, TcUser.class))
                .map((TcUser user) -> encryptor.decrypt(user))
                .map(Optional::of)
                .onErrorReturn(Optional.empty());
    }

    @Override
    public Mono<Optional<SessionList>> retrieveSessions(String id) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("sessions-" + id)
                .build();

        return Mono.fromFuture(client.getObject(request, AsyncResponseTransformer.toBytes()))
                .map(BytesWrapper::asUtf8String)
                .map((String content) ->getContent(content, SessionList.class))
                .map((SessionList user) -> encryptor.decrypt(user))
                .map(Optional::of)
                .onErrorReturn(Optional.empty());
    }

    @SneakyThrows
    @Override
    public Mono<Optional<TcBrands>> getBrandById(String id) {

        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("brand-" + id)
                .build();

        return Mono.fromFuture(client.getObject(request, AsyncResponseTransformer.toBytes()))
                .map(BytesWrapper::asUtf8String)
                .map((String content) ->getContent(content, TcBrands.class))
                .map((TcBrands user) -> encryptor.decrypt(user))
                .map(Optional::of)
                .onErrorReturn(Optional.empty());
    }


    @Override
    public Mono<Optional<AppLocker>> retrieveAppLocker(String id) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("logins-" + id + ".json")
                .build();

        return Mono.fromFuture(client.getObject(request, AsyncResponseTransformer.toBytes()))
                .map(BytesWrapper::asUtf8String)
                .map((String content) ->getContent(content, AppLocker.class))
                .map((AppLocker user) -> encryptor.decrypt(user))
                .map(Optional::of)
                .onErrorResume(e -> Mono.fromCallable(() -> {
                    AppLocker ret = new AppLocker();
                    Map<String, FailedLoginList> list = new HashMap<>();
                    FailedLoginList logins = new FailedLoginList();
                    logins.setFailedLogins(new ArrayList<>());
                    list.put(app, logins);
                    ret.setLoginListMap(list);
                    return Optional.of(ret);
                }));

    }

    @SneakyThrows
    @Override
    public void saveLogins(AppLocker locker, String id) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("logins-" + id + ".json")
                .build();

        client.putObject(putObjectRequest,
                AsyncRequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(locker))));
    }
    @SneakyThrows
    @Override
    public void saveUser(TcUser user) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("user-" + user.getId())
                .build();

        client.putObject(putObjectRequest,
                AsyncRequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(user))));
    }
    @SneakyThrows
    @Override
    public void saveBrand(TcBrands brand) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("brand-" + brand.getId())
                .build();

        client.putObject(putObjectRequest,
                AsyncRequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(brand))));
    }
    @SneakyThrows
    @Override
    public void saveSessions(SessionList brand, String id) {

        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(this.s3BucketName)
                .key("sessions-" + id)
                .build();

        client.putObject(putObjectRequest,
                AsyncRequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(brand))));
    }
}
