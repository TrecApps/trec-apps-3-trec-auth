package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.SessionList;
import com.trecapps.auth.common.models.TcBrands;
import com.trecapps.auth.common.models.TcUser;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public interface IUserStorageService {


    String retrieveKey(String keyId);

    @Deprecated(since = "0.6.3")
    TcUser retrieveUser(String id) throws JsonProcessingException;

    Optional<TcUser> getAccountById(String id);

    SessionList retrieveSessions(String id) throws JsonProcessingException;

    Optional<TcBrands> getBrandById(String id);

    @Deprecated(since = "0.6.3")
    TcBrands retrieveBrand(String id) throws JsonProcessingException;
    AppLocker retrieveAppLocker(String id) throws JsonProcessingException;
    void saveLogins(AppLocker locker, String id);
    void saveUser(TcUser user);
    void saveBrand(TcBrands brand);
    void saveSessions(SessionList brand, String id);
}
