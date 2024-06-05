package com.trecapps.auth.webflux.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.cloud.Tuple;
import com.google.cloud.storage.*;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import lombok.SneakyThrows;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class GoogleCloudUserStorageServiceAsync implements IUserStorageServiceAsync
{
    Bucket client;
    Storage storage;
    String app;

    IFieldEncryptor encryptor;
    ObjectMapper objectMapper;

    GoogleCloudUserStorageServiceAsync(
            String projectId,
            String bucketName,
            String app,
            IFieldEncryptor encryptor1,
            Jackson2ObjectMapperBuilder objectMapperBuilder
            )
    {
        storage = StorageOptions.newBuilder().setProjectId(projectId).build().getService();
        client = storage.get(bucketName);

        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.encryptor = encryptor1;
    }

    @Override
    public Mono<String> retrieveKey(String keyId) {
        return Mono.just(keyId)
                .map(k -> client.get(k))
                .map((Blob object) -> new String(object.getContent(), StandardCharsets.UTF_8));
    }

    @SneakyThrows
    <T> Optional<T> retrieveObject(Blob object, Class<T> type){
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, type)));
    }

    @Override
    @SneakyThrows
    public Mono<Optional<TcUser>> getAccountById(String id) {
        return Mono.just("user-" + id)
                .map(k -> Optional.ofNullable(client.get(k)))
                .map((Optional<Blob> object) -> {
                    if(object.isPresent() && object.get().exists())
                        return retrieveObject(object.get(), TcUser.class);
                    return Optional.empty();
                });
    }

    @Override
    @Deprecated(since = "0.6.17")
    public Mono<Optional<SessionList>> retrieveSessions(String id) {

        return Mono.just("sessions-" + id)
                .map(k -> Optional.ofNullable(client.get(k)))
                .map((Optional<Blob> object) -> {
                    if(object.isPresent() && object.get().exists())
                        return retrieveObject(object.get(), SessionList.class);
                    return Optional.empty();
                });
    }

    @Override
    @SneakyThrows
    public Mono<Optional<TcBrands>> getBrandById(String id) {
        return Mono.just("brand-" + id)
                .map(k -> Optional.ofNullable(client.get(k)))
                .map((Optional<Blob> object) -> {
                    if(object.isPresent() && object.get().exists())
                        return retrieveObject(object.get(), TcBrands.class);
                    return Optional.empty();
                });
    }

    @Override
    public Mono<Optional<AppLocker>> retrieveAppLocker(String id) {
        return Mono.just("logins-" + id + ".json")
                .map(k -> Optional.ofNullable(client.get(k)))
                .map((Optional<Blob> object) -> {
                    if(object.isPresent() && object.get().exists())
                        return retrieveObject(object.get(), AppLocker.class);
                    AppLocker ret = new AppLocker();
                    Map<String, FailedLoginList> list = new HashMap<>();
                    FailedLoginList logins = new FailedLoginList();
                    logins.setFailedLogins(new ArrayList<>());
                    list.put(app, logins);
                    ret.setLoginListMap(list);
                    return Optional.of(ret);
                });
    }

    @Override
    public Mono<SessionListV2> retrieveSessionList(String id) {
        String objName = String.format("V2-sessions-%s.json", id);
        return Mono.just(objName)
                .map(k -> Optional.ofNullable(client.get(k)))
                .map((Optional<Blob> object) -> {
                    if(object.isPresent() && object.get().exists())
                        return retrieveObject(object.get(), SessionListV2.class).get();
                    return new SessionListV2();
                });
    }

    BlobInfo getBlobInfo(String object, String bucket){
        BlobId blobId = BlobId.of(bucket, object);
        return BlobInfo.newBuilder(blobId).build();
    }

    Storage.BlobTargetOption getPrecondition(BlobInfo blobInfo)
    {
        String bucketName = blobInfo.getBucket();
        String objectName = blobInfo.getName();
        if(storage.get(bucketName, objectName) == null)
            return Storage.BlobTargetOption.doesNotExist();
        return Storage.BlobTargetOption.generationMatch(
                storage.get(bucketName, objectName).getGeneration());
    }

    @Override    @SneakyThrows
    public void saveLogins(AppLocker locker, String id) {
        String objectName = "logins-" + id + ".json";
        BlobInfo blobInfo = getBlobInfo(objectName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(locker)).getBytes(StandardCharsets.UTF_8)
                , precondition);

    }

    @Override
    public Mono<Void> saveLoginsMono(AppLocker locker, String id) {
        return Mono.just(Tuple.of(locker, id))
                .doOnNext((Tuple<AppLocker, String> tuple) -> saveLogins(tuple.x(), tuple.y()))
                .then(Mono.empty());
    }

    @Override    @SneakyThrows
    public void saveUser(TcUser user) {
        String objectName = "user-" + user.getId();
        BlobInfo blobInfo = getBlobInfo(objectName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(user)).getBytes(StandardCharsets.UTF_8)
                , precondition);
    }

    @Override
    public Mono<Void> saveUserMono(TcUser user) {
        return Mono.just(user)
                .doOnNext(this::saveUser)
                .then(Mono.empty());
    }

    @Override    @SneakyThrows
    public void saveBrand(TcBrands brand) {
        String objectName = "brand-" + brand.getId();
        BlobInfo blobInfo = getBlobInfo(objectName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(brand)).getBytes(StandardCharsets.UTF_8)
                , precondition);
    }

    @Override
    public Mono<Void> saveBrandMono(TcBrands brands) {
        return Mono.just(brands)
                .doOnNext(this::saveBrand)
                .then(Mono.empty());
    }

    @Override    @SneakyThrows
    @Deprecated(since = "0.6.17")
    public void saveSessions(SessionList brand, String id) {
        String objectName = "sessions-" + id;
        BlobInfo blobInfo = getBlobInfo(objectName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(brand)).getBytes(StandardCharsets.UTF_8)
                , precondition);
    }

    @Override
    @SneakyThrows
    public void saveSessions(SessionListV2 sessions, String id) {
        String objName = String.format("V2-sessions-%s.json", id);
        BlobInfo blobInfo = getBlobInfo(objName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(sessions)).getBytes(StandardCharsets.UTF_8)
                , precondition);
    }

    @Override
    public Mono<Void> saveSessionsMono(SessionListV2 sessions, String id) {
        return Mono.just(Tuple.of(sessions, id))
                .doOnNext((Tuple<SessionListV2, String> tuple) -> saveSessions(tuple.x(), tuple.y()))
                .then(Mono.empty());
    }
}
