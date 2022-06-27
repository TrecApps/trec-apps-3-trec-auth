package com.trecapps.auth.services;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.util.BinaryData;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.models.SessionList;
import com.trecapps.auth.models.TcBrands;
import com.trecapps.auth.models.TcUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Service
public class UserStorageService {
    BlobServiceClient client;

    ObjectMapper objectMapper;

    Logger logger = LoggerFactory.getLogger(UserStorageService.class);

    @Autowired
    UserStorageService(@Value("${trecauth.storage.account-name}") String name,
                       @Value("${trecauth.storage.account-key}") String key,
                       @Value("${trecauth.storage.blob-endpoint}") String endpoint,
                       Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        AzureNamedKeyCredential credential = new AzureNamedKeyCredential(name, key);
        client = new BlobServiceClientBuilder().credential(credential).endpoint(endpoint).buildClient();
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
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

        return objectMapper.readValue(data, TcUser.class);
    }

    public SessionList retrieveSessions(String id) throws JsonProcessingException {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("sessions-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return objectMapper.readValue(data, SessionList.class);
    }

    public TcBrands retrieveBrand(UUID id) throws JsonProcessingException
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("brand-" + id);

        BinaryData bData = client.downloadContent();

        String data = new String(bData.toBytes(), StandardCharsets.UTF_8);

        return objectMapper.readValue(data, TcBrands.class);
    }

    public void saveUser(TcUser user)
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("user-" + user.getId());

        client.upload(BinaryData.fromObject(user),true);
    }

    public void saveBrand(TcBrands brand)
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("brand-" + brand.getId());

        client.upload(BinaryData.fromObject(brand), true);
    }

    public void saveSessions(SessionList brand, String id)
    {
        BlobContainerClient containerClient = client.getBlobContainerClient("trec-apps-users");

        BlobClient client = containerClient.getBlobClient("sessions-" + id);

        client.upload(BinaryData.fromObject(brand), true);
    }
}
