package com.trecapps.auth.webflux.services;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.util.BinaryData;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.*;
import com.azure.storage.blob.specialized.BlobAsyncClientBase;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.encryptors.IFieldEncryptor;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;


public class AzureBlobUserStorageServiceAsync implements IUserStorageServiceAsync {

    BlobServiceAsyncClient client;
    BlobContainerAsyncClient containerClient;

    ObjectMapper objectMapper;


    String app;

    IFieldEncryptor encryptor;


    AzureBlobUserStorageServiceAsync(String name,
                       String key,
                       String endpoint,
                       String containerName,
                       String app,
                       IFieldEncryptor encryptor1,
                       Jackson2ObjectMapperBuilder objectMapperBuilder)
    {
        AzureNamedKeyCredential credential = new AzureNamedKeyCredential(name, key);
        client = new BlobServiceClientBuilder().credential(credential).endpoint(endpoint).buildAsyncClient();
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.encryptor = encryptor1;
        containerClient = client.getBlobContainerAsyncClient(containerName);
    }

    AzureBlobUserStorageServiceAsync(
            String endpoint,
            String containerName,
            String app,
            IFieldEncryptor encryptor1,
            Jackson2ObjectMapperBuilder objectMapperBuilder
    ){
        client = new BlobServiceClientBuilder().credential(new DefaultAzureCredentialBuilder().build()).endpoint(endpoint).buildAsyncClient();
        objectMapper = objectMapperBuilder.createXmlMapper(false).build();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        this.app = app;
        this.encryptor = encryptor1;
        containerClient = client.getBlobContainerAsyncClient(containerName);
    }

    @Override
    public Mono<String> retrieveKey(String keyId)
    {
        return Mono.just(keyId)
                .map(k -> containerClient.getBlobAsyncClient(k))
                .map(BlobAsyncClientBase::downloadContent)
                .flatMap((Mono<BinaryData> bData)->
                        bData.map((BinaryData bd) ->new String(bd.toBytes(), StandardCharsets.UTF_8)));
    }

    <T> Mono<Optional<T>> downloadContent(BlobAsyncClient client, Class<T> type){
        return Mono.just(client)
                .map(BlobAsyncClient::downloadContent)
                .flatMap((Mono<BinaryData> bData)->
                        bData.map((BinaryData bd) -> {
                            T obj = bd.toObject(type);
                            obj = encryptor.decrypt(obj);
                            return Optional.of(obj);
                        }));

    }

    @Override
    public Mono<Optional<TcUser>> getAccountById(String id){
        BlobAsyncClient client = containerClient.getBlobAsyncClient("user-" + id);
        return Mono.just(client)
                .map(BlobAsyncClientBase::exists)
                .flatMap((Mono<Boolean> exists) ->
                        exists.flatMap((Boolean e) -> !e ? Mono.just(Optional.empty()) : downloadContent(client, TcUser.class)));
    }

    @Override
    public Mono<Optional<SessionList>> retrieveSessions(String id) {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("sessions-" + id);
        return Mono.just(client)
                .map(BlobAsyncClientBase::exists)
                .flatMap((Mono<Boolean> exists) ->
                        exists.flatMap((Boolean e) -> !e ? Mono.just(Optional.empty()) : downloadContent(client, SessionList.class)));
    }

    @Override
    public Mono<Optional<TcBrands>> getBrandById(String id) {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("brand-" + id);
        return Mono.just(client)
                .map(BlobAsyncClientBase::exists)
                .flatMap((Mono<Boolean> exists) ->
                        exists.flatMap((Boolean e) -> !e ? Mono.just(Optional.empty()) : downloadContent(client, TcBrands.class)));
    }

    @Override
    public Mono<Optional<AppLocker>> retrieveAppLocker(String id)
    {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("brand-" + id);
        return Mono.just(client)
                .map(BlobAsyncClientBase::exists)
                .flatMap((Mono<Boolean> exists) ->
                        exists.flatMap((Boolean e) ->
                        {
                            if(e)
                                return downloadContent(client, AppLocker.class);
                            AppLocker ret = new AppLocker();
                            Map<String, FailedLoginList> list = new HashMap<>();
                            FailedLoginList logins = new FailedLoginList();
                            logins.setFailedLogins(new ArrayList<>());
                            list.put(app, logins);
                            ret.setLoginListMap(list);
                            return Mono.just(Optional.of(ret));
                        }));
    }

    @Override
    public void saveLogins(AppLocker locker, String id)
    {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("logins-" + id + ".json");

        client.upload(BinaryData.fromObject(encryptor.encrypt(locker)),true).subscribe();
    }

    @Override
    public void saveUser(TcUser user)
    {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("user-" + user.getId());

        client.upload(BinaryData.fromObject(encryptor.encrypt(user)),true).subscribe();
    }

    @Override
    public void saveBrand(TcBrands brand)
    {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("brand-" + brand.getId());

        client.upload(BinaryData.fromObject(encryptor.encrypt(brand)), true).subscribe();
    }

    @Override
    public void saveSessions(SessionList brand, String id)
    {
        BlobAsyncClient client = containerClient.getBlobAsyncClient("sessions-" + id);

        client.upload(BinaryData.fromObject(encryptor.encrypt(brand)), true).subscribe();
    }
}
