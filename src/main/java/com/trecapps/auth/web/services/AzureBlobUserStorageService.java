package com.trecapps.auth.web.services;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.util.BinaryData;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;


public class AzureBlobUserStorageService implements IUserStorageService{
    BlobServiceClient client;
    BlobContainerClient containerClient;

    ObjectMapper objectMapper;

    Logger logger = LoggerFactory.getLogger(AzureBlobUserStorageService.class);

    String app;

    IFieldEncryptor encryptor;


    AzureBlobUserStorageService(String name,
                       String key,
                       String endpoint,
                       String containerName,
                       String app,
                       IFieldEncryptor encryptor1,
                       Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        AzureNamedKeyCredential credential = new AzureNamedKeyCredential(name, key);
        client = new BlobServiceClientBuilder().credential(credential).endpoint(endpoint).buildClient();
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.encryptor = encryptor1;
        containerClient = client.getBlobContainerClient(containerName);
    }

    AzureBlobUserStorageService(
            String endpoint,
            String containerName,
            String app,
            IFieldEncryptor encryptor1,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ){
        client = new BlobServiceClientBuilder().credential(new DefaultAzureCredentialBuilder().build()).endpoint(endpoint).buildClient();
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.encryptor = encryptor1;
        containerClient = client.getBlobContainerClient(containerName);
    }

    @Override
    public String retrieveKey(String keyId)
    {


        BlobClient client = containerClient.getBlobClient(keyId);

        BinaryData bData = client.downloadContent();

        return new String(bData.toBytes(), StandardCharsets.UTF_8);
    }

    @Override
    public TcUser retrieveUser(String id) throws JsonProcessingException {

        BlobClient client = containerClient.getBlobClient("user-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, TcUser.class));
    }

    @Override
    public Optional<TcUser> getAccountById(String id){

        BlobClient client = containerClient.getBlobClient("user-" + id);
        if(!client.exists())
            return Optional.empty();
        BinaryData bData = client.downloadContent();

        return Optional.of(encryptor.decrypt(bData.toObject(TcUser.class)));
    }

    @Override
    public SessionList retrieveSessions(String id) throws JsonProcessingException {
        BlobClient client = containerClient.getBlobClient("sessions-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, SessionList.class));
    }

    @Override
    public Optional<TcBrands> getBrandById(String id) {
        BlobClient client = containerClient.getBlobClient("brand-" + id);
        if(!client.exists())
            return Optional.empty();
        BinaryData bData = client.downloadContent();
        return Optional.of(encryptor.decrypt(bData.toObject(TcBrands.class)));
    }

    @Override
    public TcBrands retrieveBrand(String id) throws JsonProcessingException
    {
        BlobClient client = containerClient.getBlobClient("brand-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, TcBrands.class));
    }

    @Override
    public AppLocker retrieveAppLocker(String id) throws JsonProcessingException
    {
         BlobClient client = containerClient.getBlobClient("logins-" + id + ".json");

        if(!client.exists())
        {
            AppLocker ret = new AppLocker();
            Map<String, FailedLoginList> list = new HashMap<>();
            FailedLoginList logins = new FailedLoginList();
            logins.setFailedLogins(new ArrayList<>());
            list.put(app, logins);
            ret.setLoginListMap(list);
            return ret;
        }
        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, AppLocker.class));
    }

    @Override
    @SneakyThrows
    public SessionListV2 retrieveSessionList(String id) {
        String objName = String.format("V2-sessions-%s.json", id);
        BlobClient client = containerClient.getBlobClient(objName);

        if(!client.exists())
            return new SessionListV2();
        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, SessionListV2.class));

    }

    @Override
    public void saveLogins(AppLocker locker, String id)
    {
        BlobClient client = containerClient.getBlobClient("logins-" + id + ".json");

        client.upload(BinaryData.fromObject(encryptor.encrypt(locker)),true);
    }

    @Override
    public void saveUser(TcUser user)
    {
        BlobClient client = containerClient.getBlobClient("user-" + user.getId());

        client.upload(BinaryData.fromObject(encryptor.encrypt(user)),true);
    }

    @Override
    public void saveBrand(TcBrands brand)
    {
        BlobClient client = containerClient.getBlobClient("brand-" + brand.getId());

        client.upload(BinaryData.fromObject(encryptor.encrypt(brand)), true);
    }

    @Override
    public void saveSessions(SessionList brand, String id)
    {
        BlobClient client = containerClient.getBlobClient("sessions-" + id);

        client.upload(BinaryData.fromObject(encryptor.encrypt(brand)), true);
    }

    @Override
    public void saveSessions(SessionListV2 sessions, String id) {
        BlobClient client = containerClient.getBlobClient(String.format("V2-sessions-%s.json", id));

        client.upload(BinaryData.fromObject(encryptor.encrypt(sessions)), true);
    }
}
