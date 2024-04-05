package com.trecapps.auth.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.AppLocker;
import com.trecapps.auth.models.SessionList;
import com.trecapps.auth.models.TcBrands;
import com.trecapps.auth.models.TcUser;
import org.springframework.stereotype.Service;

@Service
public interface IUserStorageService {


    String retrieveKey(String keyId);
    TcUser retrieveUser(String id) throws JsonProcessingException;
    SessionList retrieveSessions(String id) throws JsonProcessingException;
    TcBrands retrieveBrand(String id) throws JsonProcessingException;
    AppLocker retrieveAppLocker(String id) throws JsonProcessingException;
    void saveLogins(AppLocker locker, String id);
    void saveUser(TcUser user);
    void saveBrand(TcBrands brand);
    void saveSessions(SessionList brand, String id);
}
