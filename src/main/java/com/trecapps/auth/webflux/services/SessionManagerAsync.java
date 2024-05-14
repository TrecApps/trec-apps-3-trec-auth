package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.SessionManagerBase;
import com.trecapps.auth.common.models.Session;
import com.trecapps.auth.common.models.SessionList;
import com.trecapps.auth.common.models.TokenTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class SessionManagerAsync extends SessionManagerBase {
    IUserStorageServiceAsync userStorageService;

    @Autowired
    SessionManagerAsync(
            IUserStorageServiceAsync userStorageService1,
            @Value("${trecauth.app.agnostic:false}") boolean agnostic
    ){
        super(agnostic);
        this.userStorageService = userStorageService1;
    }

    public Mono<Optional<TokenTime>> addSession(String app, String userId, String clientInfo, boolean expires){

        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent()){
                        OffsetDateTime exp = expires ?
                                OffsetDateTime.now().plusMinutes(10) : null;
                        SessionList sessions = oSessionList.get();
                        String ret = sessions.addNewSession(app,getDeviceInfo(clientInfo), exp);
                        userStorageService.saveSessions(sessions, userId);
                        TokenTime tokenTime = new TokenTime();
                        tokenTime.setExpiration(exp);
                        tokenTime.setSession(ret);
                        return Optional.of(tokenTime);
                    }
                    return Optional.empty();
                });
    }

    public Mono<Boolean> prepNewUser(String userId)
    {
        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                        return false;
                    SessionList newList = new SessionList(new ArrayList<>());
                    userStorageService.saveSessions(newList, userId);
                    return true;
                });
    }

    public Mono<Boolean> updateSessionExpiration(String userId, String session, OffsetDateTime time)
    {
        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                    {
                        SessionList sessions = oSessionList.get();
                        for(Session session1 : sessions.getSessions())
                        {
                            if(session.equals(session1.getSessionId()))
                            {
                                session1.setExpiration(time);
                                userStorageService.saveSessions(sessions, userId);
                                return true;
                            }
                        }
                    }
                    return false;

                });
    }

    public Mono<Boolean> setBrand(String userId, String session, String brand)
    {
        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                    {
                        SessionList sessions = oSessionList.get();
                        for(Session session1 : sessions.getSessions())
                        {
                            if(session.equals(session1.getSessionId()))
                            {
                                session1.setBrandId(brand);
                                userStorageService.saveSessions(sessions, userId);
                                return true;
                            }
                        }
                    }
                    return false;
                });
    }

    public Mono<Optional<String>> getBrand(String userId, String session){

        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                    {
                        SessionList sessions = oSessionList.get();
                        for(Session session1 : sessions.getSessions())
                        {
                            if(session.equals(session1.getSessionId()))
                            {
                                return Optional.of(session1.getBrandId());

                            }
                        }
                    }
                    return Optional.empty();
                });
    }

    public Mono<List<Session>> getSessionList(String userId)
    {
        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                        return oSessionList.get().getSessions();
                    return new ArrayList<>();
                });
    }

    public Mono<Boolean> removeSession(String userId, String sessionId){
        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                    {
                        SessionList sessions = oSessionList.get();
                        List<Session> savedSessions = new ArrayList<>();

                        for(Session session : sessions.getSessions())
                        {
                            if(!sessionId.equals(session.getSessionId()))
                                savedSessions.add(session);
                        }
                        sessions.setSessions(savedSessions);
                        userStorageService.saveSessions(sessions, userId);
                        return true;
                    }
                    return false;
                });
    }

    public Mono<Boolean> isValidSession(String userId, String app, String sessionId)
    {
        return userStorageService.retrieveSessions(userId)
                .map((Optional<SessionList> oSessionList) -> {
                    if(oSessionList.isPresent())
                    {
                        SessionList sessions = oSessionList.get();
                        return sessions.isValidSession(sessionId, appAgnostic ? null : app);
                    }
                    return false;
                });
    }
}
