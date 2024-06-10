package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.SessionManagerBase;
import com.trecapps.auth.common.models.SessionApp;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.SessionV2;
import com.trecapps.auth.common.models.TokenTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;
import java.util.List;

@Service
public class V2SessionManagerAsync  extends SessionManagerBase {
    IUserStorageServiceAsync userStorageService;
    boolean appAgnostic;
    @Autowired
    V2SessionManagerAsync(
            IUserStorageServiceAsync userStorageService1,
            @Value("${trecauth.app.agnostic:false}")boolean appAgnostic1
    ){
        super(true);
        this.userStorageService = userStorageService1;
        this.appAgnostic = appAgnostic1;
    }

    public Mono<TokenTime> addSession(String app, String userId, String clientInfo, boolean expires)
    {
        return userStorageService.retrieveSessionList(userId)
                .flatMap((SessionListV2 sessionList)-> {
                    OffsetDateTime exp = expires ?
                            OffsetDateTime.now().plusMinutes(10) : null;

                    SessionV2 session = prepareNewSession(
                            sessionList,
                            getDeviceInfo(clientInfo),
                            app,
                            exp);

                    return userStorageService.saveSessionsMono(sessionList, userId)
                            .then(Mono.just(new TokenTime()))
                            .map((TokenTime tokenTime) -> {
                                tokenTime.setExpiration(exp);
                                tokenTime.setSession(session.getDeviceId());
                                return tokenTime;
                            });

                });
    }

    public Mono<SessionListV2> updateSessionExpiration(String userId, String sessionId, OffsetDateTime time) {
        return userStorageService.retrieveSessionList(userId)
                .doOnNext((SessionListV2 sessions) -> {
                    SessionV2 session = sessions.getSessionById(sessionId);
                    session.setExpiration(time);
                    userStorageService.saveSessions(sessions, userId);
                });
    }

    public Mono<SessionListV2> setBrandMono(String userId, String sessionId, String brand, String app, boolean updateBrand)
    {
        return userStorageService.retrieveSessionList(userId)
                .doOnNext((SessionListV2 sessions) -> {
                    SessionV2 session = sessions.getSessionById(sessionId);

                    session.setApp(app, brand, updateBrand);

                    userStorageService.saveSessions(sessions, userId);
                });
    }

    public Mono<SessionListV2> setBrandMono(String userId, String sessionId, String brand, String app)
    {
        return setBrandMono(userId, sessionId, brand, app, true);
    }

    public void setBrand(String userId, String sessionId, String brand, String app){
        setBrand(userId, sessionId, brand, app, true);
    }

    public void setBrand(String userId, String sessionId, String brand, String app, boolean updateBrand) {
        setBrandMono(userId, sessionId, brand, app, updateBrand).subscribe();
    }

    public Mono<String> getBrand(String userId, String sessionId, String app){
        return userStorageService.retrieveSessionList(userId)
                .map((SessionListV2 sessions) -> {
                    SessionV2 session = sessions.getSessionById(sessionId);

                    SessionApp sessionApp = session.getApp(app);
                    return sessionApp == null ? null : sessionApp.getBrandId();
                });
    }

    public Mono<List<SessionV2>> getSessionList(String userId){
        return userStorageService.retrieveSessionList(userId)
                .map(SessionListV2::getSessions);
    }

    public Mono<Void> removeSessionMono(String userId, String sessionId){
        return userStorageService.retrieveSessionList(userId)
                .flatMap((SessionListV2 sessions) -> {
                    sessions.setSessions(sessions.getSessions()
                            .stream()
                            .filter((SessionV2 session) -> !session.getDeviceId().equals(sessionId))
                            .toList());
                    return userStorageService.saveSessionsMono(sessions, userId);})
                .then(Mono.empty());
    }

    public void removeSession(String userId, String sessionId){
        removeSessionMono(userId, sessionId).subscribe();
    }

    public void blockApp(String userId, String sessionId, String app){
        userStorageService.retrieveSessionList(userId)
                .doOnNext((SessionListV2 sessions) -> {
                    SessionV2 session = sessions.getSessionById(sessionId);

                    session.setApps(session.getApps()
                            .stream()
                            .filter((SessionApp sessionApp) -> !sessionApp.getApp().equals(app))
                            .toList());
                    List<String> blockedApps = session.getBlockedApps();
                    if (!blockedApps.contains(app))
                        blockedApps.add(app);
                    userStorageService.saveSessions(sessions, userId);
                }).subscribe();
    }

    public Mono<Boolean> isValidSession(String userId, String app, String sessionId){
        return userStorageService.retrieveSessionList(userId)
                .map((SessionListV2 sessions) -> {
                    SessionV2 session = sessions.getSessionById(sessionId);
                    if(session == null || session.isExpired() || session.getBlockedApps().contains(app))
                        return false;

                    return appAgnostic || session.getApps().stream().anyMatch((SessionApp sessionApp) -> sessionApp.getApp().equals(app));

                });

    }
}
