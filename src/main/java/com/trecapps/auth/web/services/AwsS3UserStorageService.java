package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import lombok.SneakyThrows;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class AwsS3UserStorageService implements IUserStorageService{

    S3Client client;

    ObjectMapper objectMapper;
    String app;

    String s3BucketName;

    IFieldEncryptor encryptor;

    AwsS3UserStorageService(String clientName,
                            String clientSecret,
                            String s3Region,
                            String s3BucketName,
                            String app,
                            IFieldEncryptor encryptor1,
                            Jackson2ObjectMapperBuilder objectMapperBuilder){
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(clientName, clientSecret)
                ))
                .region(Region.of(s3Region)).build();

        setUp(s3BucketName, app, encryptor1, objectMapperBuilder);
    }

    AwsS3UserStorageService(
                            String s3Region,
                            String s3BucketName,
                            String app,
                            IFieldEncryptor encryptor1,
                            Jackson2ObjectMapperBuilder objectMapperBuilder){
        client = S3Client.builder()
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

    @SneakyThrows(IOException.class)
    @Override
    public String retrieveKey(String keyId) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key(keyId)
                .build();
        byte[] response = client.getObject(request).readAllBytes();
        return new String(response, StandardCharsets.UTF_8);
    }

    @SneakyThrows(IOException.class)
    @Override
    @Deprecated(since = "0.6.3")
    public TcUser retrieveUser(String id) throws JsonProcessingException {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key("user-"+ id)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return encryptor.decrypt(objectMapper.readValue(bytes, TcUser.class));
        } catch(NoSuchKeyException e){
            return null;
        }
    }

    @SneakyThrows
    @Override
    public Optional<TcUser> getAccountById(String id) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key("user-"+ id)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return Optional.of(encryptor.decrypt(objectMapper.readValue(bytes, TcUser.class)));
        } catch(NoSuchKeyException e){
            return Optional.empty();
        }
    }

    @SneakyThrows(IOException.class)
    @Override
    public SessionList retrieveSessions(String id) throws JsonProcessingException {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key("sessions-"+ id)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return encryptor.decrypt(objectMapper.readValue(bytes, SessionList.class));
        } catch(NoSuchKeyException e){
            return null;
        }
    }

    @SneakyThrows
    @Override
    public Optional<TcBrands> getBrandById(String id) {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key("brand-"+ id)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return Optional.of(encryptor.decrypt(objectMapper.readValue(bytes, TcBrands.class)));
        } catch(NoSuchKeyException e){
            return Optional.empty();
        }
    }

    @SneakyThrows(IOException.class)
    @Override
    @Deprecated(since = "0.6.3")
    public TcBrands retrieveBrand(String id) throws JsonProcessingException {
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key("brand-"+ id)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return encryptor.decrypt(objectMapper.readValue(bytes, TcBrands.class));
        } catch(NoSuchKeyException e){
            return null;
        }
    }

    @SneakyThrows(IOException.class)
    @Override
    public AppLocker retrieveAppLocker(String id) throws JsonProcessingException {
        String objectName = "logins-" + id + ".json";

        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key(objectName)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return encryptor.decrypt(objectMapper.readValue(bytes, AppLocker.class));
        } catch(NoSuchKeyException e){
            AppLocker ret = new AppLocker();
            Map<String, FailedLoginList> list = new HashMap<>();
            FailedLoginList logins = new FailedLoginList();
            logins.setFailedLogins(new ArrayList<>());
            list.put(app, logins);
            ret.setLoginListMap(list);
            return ret;
        }
    }

    @Override
    @SneakyThrows
    public SessionListV2 retrieveSessionList(String id) {
        String objName = String.format("V2-sessions-%s.json", id);
        GetObjectRequest request = GetObjectRequest.builder()
                .bucket(s3BucketName)
                .key(objName)
                .build();

        try{
            byte[] bytes = client.getObject(request).readAllBytes();
            return encryptor.decrypt(objectMapper.readValue(bytes, SessionListV2.class));
        } catch(NoSuchKeyException e){
            return new SessionListV2();
        }
    }

    @SneakyThrows
    @Override
    public void saveLogins(AppLocker locker, String id) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key("logins-" + id + ".json")
                .build();

        client.putObject(putObjectRequest, RequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(locker))));

    }
    @SneakyThrows
    @Override
    public void saveUser(TcUser user) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key("user-" + user.getId())
                .build();

        client.putObject(putObjectRequest, RequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(user))));
    }

    @SneakyThrows
    @Override
    public void saveBrand(TcBrands brand) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key("brand-" + brand.getId())
                .build();

        client.putObject(putObjectRequest, RequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(brand))));
    }
    @SneakyThrows
    @Override
    public void saveSessions(SessionList brand, String id) {

        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key("sessions-" + id)
                .build();

        client.putObject(putObjectRequest, RequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(brand))));
    }

    @Override
    @SneakyThrows
    public void saveSessions(SessionListV2 sessions, String id) {
        String objName = String.format("V2-sessions-%s.json", id);
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key(objName)
                .build();

        client.putObject(putObjectRequest, RequestBody.fromString(objectMapper.writeValueAsString(encryptor.encrypt(sessions))));
    }
}
