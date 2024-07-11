package com.trecapps.auth.web.services;

import com.trecapps.auth.common.SessionManagerBase;
import com.trecapps.auth.common.models.SessionApp;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.SessionV2;
import com.trecapps.auth.common.models.TokenTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;

@Service
public class V2SessionManager extends SessionManagerBase {

    boolean appAgnostic;

    @Autowired
    V2SessionManager(IUserStorageService userStorageService1,
            @Value("${trecauth.app.agnostic:false}")boolean appAgnostic1){
        super(true);
        userStorageService = userStorageService1;
        this.appAgnostic = appAgnostic1;
    }

    IUserStorageService userStorageService;

    public TokenTime addSession(String app, String userId, String clientInfo, boolean expires){
        SessionListV2 sessionList = userStorageService.retrieveSessionList(userId);

        OffsetDateTime exp = expires ?
                OffsetDateTime.now().plusMinutes(10) : null;

        SessionV2 session = prepareNewSession(
                sessionList,
                getDeviceInfo(clientInfo),
                app,
                exp);

        userStorageService.saveSessions(sessionList, userId);
        TokenTime tokenTime = new TokenTime();
        tokenTime.setExpiration(exp);
        tokenTime.setSession(session.getDeviceId());
        return tokenTime;
    }

    public void updateSessionExpiration(String userId, String sessionId, OffsetDateTime time) {
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        SessionV2 session = sessions.getSessionById(sessionId);
        session.setExpiration(time);
        userStorageService.saveSessions(sessions, userId);
    }

    public void setBrand(String userId, String sessionId, String brand, String app)
    {
        setBrand(userId, sessionId, brand, app, true);
    }

    public void setBrand(String userId, String sessionId, String brand, String app, boolean doUpdate) {
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        SessionV2 session = sessions.getSessionById(sessionId);

        session.setApp(app, brand, doUpdate);

        userStorageService.saveSessions(sessions, userId);
    }

    public String getBrand(String userId, String sessionId, String app){
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        SessionV2 session = sessions.getSessionById(sessionId);

        SessionApp sessionApp = session.getApp(app);
        String ret = sessionApp == null ? null : sessionApp.getBrandId();
        if(ret == null)
            ret = "";
        return ret;
    }

    public List<SessionV2> getSessionList(String userId){
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        return sessions.getSessions();
    }

    public void removeSession(String userId, String sessionId){
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        sessions.setSessions(sessions.getSessions()
                .stream()
                .filter((SessionV2 session) -> !session.getDeviceId().equals(sessionId))
                .toList());
        userStorageService.saveSessions(sessions, userId);
    }

    public void blockApp(String userId, String sessionId, String app){
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        SessionV2 session = sessions.getSessionById(sessionId);

        session.setApps(session.getApps()
                .stream()
                        .filter((SessionApp sessionApp) -> !sessionApp.getApp().equals(app))
                .toList());
        List<String> blockedApps = session.getBlockedApps();
        if(!blockedApps.contains(app))
            blockedApps.add(app);
        userStorageService.saveSessions(sessions, userId);
    }

    public boolean isValidSession(String userId, String app, String sessionId){
        SessionListV2 sessions = userStorageService.retrieveSessionList(userId);
        SessionV2 session = sessions.getSessionById(sessionId);
        if(session == null || session.isExpired() || session.getBlockedApps().contains(app))
            return false;

        return appAgnostic || session.getApps().stream().anyMatch((SessionApp sessionApp) -> sessionApp.getApp().equals(app));
    }
}
