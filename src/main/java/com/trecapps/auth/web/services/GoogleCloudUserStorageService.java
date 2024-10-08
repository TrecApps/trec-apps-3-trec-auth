package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.cloud.storage.*;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import lombok.SneakyThrows;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class GoogleCloudUserStorageService implements IUserStorageService
{
    Bucket client;
    Storage storage;
    String app;

    IFieldEncryptor encryptor;
    ObjectMapper objectMapper;

    GoogleCloudUserStorageService(
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
    public String retrieveKey(String keyId) {
        Blob object = client.get(keyId);
        return new String(object.getContent(), StandardCharsets.UTF_8);
    }

    @Override
    public TcUser retrieveUser(String id) throws JsonProcessingException {
        Blob object = client.get("user-" + id);
        if(object == null || !object.exists())
            return null;
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, TcUser.class));
    }

    @Override
    @SneakyThrows
    public Optional<TcUser> getAccountById(String id) {
        Blob object = client.get("user-" + id);
        if(object == null || !object.exists())
            return Optional.empty();
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, TcUser.class)));
    }

    @Override
    @SneakyThrows
    public Optional<TcBrands> getBrandById(String id) {
        Blob object = client.get("brand-" + id);
        if(object == null || !object.exists())
            return Optional.empty();
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, TcBrands.class)));
    }

    @Override
    public TcBrands retrieveBrand(String id) throws JsonProcessingException {
        Blob object = client.get("brand-" + id);
        if(object == null || !object.exists())
            return null;
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, TcBrands.class));
    }

    @Override
    public AppLocker retrieveAppLocker(String id) throws JsonProcessingException {
        String objectName = "logins-" + id + ".json";
        Blob object = client.get(objectName);
        if(object == null || !object.exists()){
            AppLocker ret = new AppLocker();
            Map<String, FailedLoginList> list = new HashMap<>();
            FailedLoginList logins = new FailedLoginList();
            logins.setFailedLogins(new ArrayList<>());
            list.put(app, logins);
            ret.setLoginListMap(list);
            return ret;
        }
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, AppLocker.class));
    }

    @Override
    @SneakyThrows
    public SessionListV2 retrieveSessionList(String id) {
        String objName = String.format("V2-sessions-%s.json", id);
        Blob object = client.get(objName);
        if(object == null || !object.exists()){
            return new SessionListV2();
        }
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, SessionListV2.class));
    }

    BlobInfo getBlobInfo(String object, String bucket){
        BlobId blobId = BlobId.of(bucket, object);
        return BlobInfo.newBuilder(blobId).build();
    }

    Storage.BlobTargetOption getPrecondition(BlobInfo blobInfo)
    {
        String bucketName = blobInfo.getBucket();
        String objectName = blobInfo.getName();
        Blob object = storage.get(bucketName, objectName);
        if( object == null)
            return Storage.BlobTargetOption.doesNotExist();
        return Storage.BlobTargetOption.generationMatch(
                object.getGeneration());
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

    @Override    @SneakyThrows
    public void saveUser(TcUser user) {
        checkUserPermissions(user);
        String objectName = "user-" + user.getId();
        BlobInfo blobInfo = getBlobInfo(objectName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(user)).getBytes(StandardCharsets.UTF_8)
                , precondition);
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

    @Override @SneakyThrows
    public void saveSessions(SessionListV2 sessions, String id) {
        String objName = String.format("V2-sessions-%s.json", id);

        BlobInfo blobInfo = getBlobInfo(objName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(sessions)).getBytes(StandardCharsets.UTF_8)
                , precondition);
    }
}
