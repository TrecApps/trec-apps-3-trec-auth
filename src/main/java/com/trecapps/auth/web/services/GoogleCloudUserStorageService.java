package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.cloud.storage.*;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.encryptors.IFieldEncryptor;
import com.trecapps.auth.models.*;
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
        if(!object.exists())
            return null;
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, TcUser.class));
    }

    @Override
    @SneakyThrows
    public Optional<TcUser> getAccountById(String id) {
        Blob object = client.get("user-" + id);
        if(!object.exists())
            return Optional.empty();
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, TcUser.class)));
    }

    @Override
    public SessionList retrieveSessions(String id) throws JsonProcessingException {
        Blob object = client.get("sessions-" + id);
        if(!object.exists())
            return null;
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, SessionList.class));
    }

    @Override
    @SneakyThrows
    public Optional<TcBrands> getBrandById(String id) {
        Blob object = client.get("brand-" + id);
        if(!object.exists())
            return Optional.empty();
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, TcBrands.class)));
    }

    @Override
    public TcBrands retrieveBrand(String id) throws JsonProcessingException {
        Blob object = client.get("brand-" + id);
        if(!object.exists())
            return null;
        String data = new String(object.getContent(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, TcBrands.class));
    }

    @Override
    public AppLocker retrieveAppLocker(String id) throws JsonProcessingException {
        String objectName = "logins-" + id + ".json";
        Blob object = client.get(objectName);
        if(!object.exists()){
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

    BlobInfo getBlobInfo(String bucket, String object){
        BlobId blobId = BlobId.of(bucket, object);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();
        return blobInfo;
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

    @Override    @SneakyThrows
    public void saveSessions(SessionList brand, String id) {
        String objectName = "sessions-" + id;
        BlobInfo blobInfo = getBlobInfo(objectName, client.getName());
        Storage.BlobTargetOption precondition = getPrecondition(blobInfo);

        storage.create(
                blobInfo,
                objectMapper.writeValueAsString(encryptor.encrypt(brand)).getBytes(StandardCharsets.UTF_8)
                , precondition);
    }
}
