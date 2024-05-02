package com.trecapps.auth.services.core;


import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.encryptors.IFieldEncryptor;
import com.trecapps.auth.models.*;
import lombok.SneakyThrows;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class AwsS3UserStorageService implements IUserStorageService{

    AmazonS3 client;
    ObjectMapper objectMapper;
    String app;

    String s3BucketName;

    IFieldEncryptor encryptor;

    AwsS3UserStorageService(String clientName,
                            String clientSecret,
                            String s3Endpoint,
                            String s3Region,
                            String s3BucketName,
                            String app,
                            IFieldEncryptor encryptor1,
                            Jackson2ObjectMapperBuilder objectMapperBuilder){
        client = AmazonS3Client
                .builder()
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(clientName, clientSecret))).
        withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(s3Endpoint,s3Region)).build();

        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.s3BucketName = s3BucketName;
        this.encryptor = encryptor1;
    }

    @SneakyThrows(IOException.class)
    @Override
    public String retrieveKey(String keyId) {
        S3Object object = client.getObject(s3BucketName, keyId);
        S3ObjectInputStream stream = object.getObjectContent();
        return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    }

    @SneakyThrows(IOException.class)
    @Override
    public TcUser retrieveUser(String id) throws JsonProcessingException {
        if(!client.doesObjectExist(s3BucketName,"user-" + id))
            return null;
        S3Object object = client.getObject(s3BucketName, "user-" + id);
        S3ObjectInputStream stream = object.getObjectContent();
        String data = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, TcUser.class));
    }

    @SneakyThrows
    @Override
    public Optional<TcUser> getAccountById(String id) {
        if(!client.doesObjectExist(s3BucketName,"user-" + id))
            return Optional.empty();
        S3Object object = client.getObject(s3BucketName, "user-" + id);

        S3ObjectInputStream stream = object.getObjectContent();
        String data = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, TcUser.class)));
    }

    @SneakyThrows(IOException.class)
    @Override
    public SessionList retrieveSessions(String id) throws JsonProcessingException {
        S3Object object = client.getObject(s3BucketName, "sessions-" + id);
        S3ObjectInputStream stream = object.getObjectContent();
        String data = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, SessionList.class));
    }

    @SneakyThrows
    @Override
    public Optional<TcBrands> getBrandById(String id) {
        if(client.doesObjectExist(s3BucketName, "brand-" + id))
            return Optional.empty();
        S3Object object = client.getObject(s3BucketName, "brand-" + id);
        S3ObjectInputStream stream = object.getObjectContent();
        String data = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return Optional.of(encryptor.decrypt(objectMapper.readValue(data, TcBrands.class)));
    }

    @SneakyThrows(IOException.class)
    @Override
    public TcBrands retrieveBrand(String id) throws JsonProcessingException {
        if(client.doesObjectExist(s3BucketName, "brand-" + id))
            return null;
        S3Object object = client.getObject(s3BucketName, "brand-" + id);
        S3ObjectInputStream stream = object.getObjectContent();
        String data = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return encryptor.decrypt(objectMapper.readValue(data, TcBrands.class));
    }

    @SneakyThrows(IOException.class)
    @Override
    public AppLocker retrieveAppLocker(String id) throws JsonProcessingException {
        String objectName = "logins-" + id + ".json";

        if(!client.doesObjectExist(s3BucketName, objectName))
        {
            AppLocker ret = new AppLocker();
            Map<String, FailedLoginList> list = new HashMap<>();
            FailedLoginList logins = new FailedLoginList();
            logins.setFailedLogins(new ArrayList<>());
            list.put(app, logins);
            ret.setLoginListMap(list);
            return ret;
        }

        S3Object object = client.getObject(s3BucketName, objectName);
        S3ObjectInputStream stream = object.getObjectContent();
        String data = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return objectMapper.readValue(data, AppLocker.class);
    }

    @SneakyThrows
    @Override
    public void saveLogins(AppLocker locker, String id) {
        PutObjectRequest putRequest = new PutObjectRequest(
                s3BucketName,
                "logins-" + id + ".json",
                objectMapper.writeValueAsString(encryptor.encrypt(locker)));
        client.putObject(putRequest);
    }
    @SneakyThrows
    @Override
    public void saveUser(TcUser user) {
        PutObjectRequest putRequest = new PutObjectRequest(
                s3BucketName,
                "user-" + user.getId(),
                objectMapper.writeValueAsString(encryptor.encrypt(user)));
        client.putObject(putRequest);
    }
    @SneakyThrows
    @Override
    public void saveBrand(TcBrands brand) {
        PutObjectRequest putRequest = new PutObjectRequest(
                s3BucketName,
                "brand-" + brand.getId(),
                objectMapper.writeValueAsString(encryptor.encrypt(brand)));
        client.putObject(putRequest);
    }
    @SneakyThrows
    @Override
    public void saveSessions(SessionList brand, String id) {
        PutObjectRequest putRequest = new PutObjectRequest(
                s3BucketName,
                "sessions-" + id,
                objectMapper.writeValueAsString(encryptor.encrypt(brand)));
        client.putObject(putRequest);
    }
}
