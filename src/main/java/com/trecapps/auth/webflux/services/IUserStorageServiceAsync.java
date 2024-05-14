package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.SessionList;
import com.trecapps.auth.common.models.TcBrands;
import com.trecapps.auth.common.models.TcUser;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Service
public interface IUserStorageServiceAsync {

    Mono<String> retrieveKey(String keyId);

    Mono<Optional<TcUser>> getAccountById(String id);

    Mono<Optional<SessionList>> retrieveSessions(String id) ;

    Mono<Optional<TcBrands>> getBrandById(String id);
    Mono<Optional<AppLocker>> retrieveAppLocker(String id);
    void saveLogins(AppLocker locker, String id);
    void saveUser(TcUser user);
    void saveBrand(TcBrands brand);
    void saveSessions(SessionList brand, String id);
}
