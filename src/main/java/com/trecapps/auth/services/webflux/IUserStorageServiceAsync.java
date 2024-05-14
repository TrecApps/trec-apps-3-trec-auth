package com.trecapps.auth.services.webflux;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.AppLocker;
import com.trecapps.auth.models.SessionList;
import com.trecapps.auth.models.TcBrands;
import com.trecapps.auth.models.TcUser;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Service
public interface IUserStorageServiceAsync {

    Mono<String> retrieveKey(String keyId);

    Mono<Optional<TcUser>> getAccountById(String id);

    Mono<Optional<SessionList>> retrieveSessions(String id) throws JsonProcessingException;

    Mono<Optional<TcBrands>> getBrandById(String id);
    Mono<Optional<AppLocker>> retrieveAppLocker(String id) throws JsonProcessingException;
    void saveLogins(AppLocker locker, String id);
    void saveUser(TcUser user);
    void saveBrand(TcBrands brand);
    void saveSessions(SessionList brand, String id);
}
