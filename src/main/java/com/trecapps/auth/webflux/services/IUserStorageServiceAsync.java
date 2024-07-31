package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.*;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

@Service
public interface IUserStorageServiceAsync {

    default void checkUserPermissions(TcUser user){
        List<String> authRoles = user.getAuthRoles();
        authRoles.remove("EMAIL_VERIFIED");
        authRoles.remove("PHONE_VERIFIED");
        authRoles.remove("MFA_PROVIDED");
    }

    Mono<String> retrieveKey(String keyId);

    Mono<Optional<TcUser>> getAccountById(String id);

    Mono<Optional<TcBrands>> getBrandById(String id);
    Mono<Optional<AppLocker>> retrieveAppLocker(String id);

    Mono<SessionListV2> retrieveSessionList(String id);

    default void saveLogins(AppLocker locker, String id){
        saveLoginsMono(locker, id).subscribe();
    }
    Mono<Void> saveLoginsMono(AppLocker locker, String id);


    default void saveUser(TcUser user){
        saveUserMono(user).subscribe();
    }
    Mono<Void> saveUserMono(TcUser user);

    default void saveBrand(TcBrands brand){
        saveBrandMono(brand).subscribe();
    }
    Mono<Void> saveBrandMono(TcBrands brands);

    default void saveSessions(SessionListV2 sessions, String id){
        saveSessionsMono(sessions,id).subscribe();
    }

    Mono<Void> saveSessionsMono(SessionListV2 sessions, String id);
}
