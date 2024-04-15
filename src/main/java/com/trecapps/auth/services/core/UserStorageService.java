package com.trecapps.auth.services.core;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.util.BinaryData;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.encryptors.IFieldEncryptor;
import com.trecapps.auth.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class UserStorageService {
    BlobServiceClient client;

    ObjectMapper objectMapper;

    Logger logger = LoggerFactory.getLogger(UserStorageService.class);

    String app;

    IFieldEncryptor encryptor;


    @Autowired
    UserStorageService(@Value("${trecauth.storage.account-name}") String name,
                       @Value("${trecauth.storage.account-key}") String key,
                       @Value("${trecauth.storage.blob-endpoint}") String endpoint,
                       @Value("${trecauth.app}") String app,
                       IFieldEncryptor encryptor,
                       Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        AzureNamedKeyCredential credential = new AzureNamedKeyCredential(name, key);
        client = new BlobServiceClientBuilder().credential(credential).endpoint(endpoint).buildClient();
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.encryptor = encryptor;
    }

    public String retrieveKey(String keyId)
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient(keyId);

        BinaryData bData = client.downloadContent();

        return new String(bData.toBytes(), StandardCharsets.UTF_8);
    }

    public TcUser retrieveUser(String id) throws JsonProcessingException {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("user-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, TcUser.class));
    }

    Optional<TcUser> getAccountById(String id){
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("user-" + id);
        if(!client.exists())
            return Optional.empty();
        BinaryData bData = client.downloadContent();

        return Optional.of(encryptor.decrypt(bData.toObject(TcUser.class)));
    }

    public SessionList retrieveSessions(String id) throws JsonProcessingException {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("sessions-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, SessionList.class));
    }

    public TcBrands retrieveBrand(String id) throws JsonProcessingException
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("brand-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return encryptor.decrypt(objectMapper.readValue(data, TcBrands.class));
    }

    public AppLocker retrieveAppLocker(String id) throws JsonProcessingException
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

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

    public void saveLogins(AppLocker locker, String id)
    {
        locker = encryptor.encrypt(locker);

        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("logins-" + id + ".json");

        client.upload(BinaryData.fromObject(locker),true);
    }

    public void saveUser(TcUser user)
    {
        user = encryptor.encrypt(user);
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("user-" + user.getId());

        client.upload(BinaryData.fromObject(user),true);
    }

    public void saveBrand(TcBrands brand)
    {
        brand = encryptor.encrypt(brand);
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("brand-" + brand.getId());

        client.upload(BinaryData.fromObject(brand), true);
    }

    public void saveSessions(SessionList brand, String id)
    {
        brand = encryptor.encrypt(brand);
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("sessions-" + id);

        client.upload(BinaryData.fromObject(brand), true);
    }
}
