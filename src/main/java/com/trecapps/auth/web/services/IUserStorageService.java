package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.common.models.*;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public interface IUserStorageService {

    default void checkUserPermissions(TcUser user){
        List<String> authRoles = user.getAuthRoles();
        authRoles.remove("EMAIL_VERIFIED");
        authRoles.remove("PHONE_VERIFIED");
        authRoles.remove("MFA_PROVIDED");
    }

    String retrieveKey(String keyId);

    @Deprecated(since = "0.6.3")
    TcUser retrieveUser(String id) throws JsonProcessingException;

    Optional<TcUser> getAccountById(String id);

    Optional<TcBrands> getBrandById(String id);

    @Deprecated(since = "0.6.3")
    TcBrands retrieveBrand(String id) throws JsonProcessingException;
    AppLocker retrieveAppLocker(String id) throws JsonProcessingException;

    SessionListV2 retrieveSessionList(String id);


    void saveLogins(AppLocker locker, String id);
    void saveUser(TcUser user);
    void saveBrand(TcBrands brand);
    void saveSessions(SessionListV2 sessions, String id);
}
