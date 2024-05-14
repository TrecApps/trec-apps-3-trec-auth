package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.common.SessionManagerBase;
import com.trecapps.auth.common.models.Session;
import com.trecapps.auth.common.models.SessionList;
import com.trecapps.auth.common.models.TokenTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class SessionManager extends SessionManagerBase {

    IUserStorageService userStorageService;

    @Autowired
    SessionManager(
    IUserStorageService userStorageService1,
    @Value("${trecauth.app.agnostic:false}") boolean agnostic
    ){
        super(agnostic);
        this.userStorageService = userStorageService1;
    }

    public TokenTime addSession(String app, String userId, String clientInfo, boolean expires){
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);

            OffsetDateTime exp = expires ?
                    OffsetDateTime.now().plusMinutes(10) : null;

            String ret = sessions.addNewSession(app,getDeviceInfo(clientInfo), exp);
            userStorageService.saveSessions(sessions, userId);
            TokenTime tokenTime = new TokenTime();
            tokenTime.setExpiration(exp);
            tokenTime.setSession(ret);
            return tokenTime;
        } catch (JsonProcessingException e) {
            logger.error("Error reading SessionList!", e);
            return null;
        }
    }

    public boolean prepNewUser(String userId)
    {
        try
        {
            SessionList list = userStorageService.retrieveSessions(userId);
            return false;
        }catch(Exception e)
        {
            SessionList newList = new SessionList(new ArrayList<>());
            userStorageService.saveSessions(newList, userId);
            return true;
        }
    }

    public boolean updateSessionExpiration(String userId, String session, OffsetDateTime time)
    {
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);

            for(Session session1 : sessions.getSessions())
            {
                if(session.equals(session1.getSessionId()))
                {
                    session1.setExpiration(time);
                    userStorageService.saveSessions(sessions, userId);
                    return true;
                }
            }
        } catch (JsonProcessingException e) {
            logger.error("Error reading SessionList!", e);
        }
        return false;
    }

    public boolean setBrand(String userId, String session, String brand)
    {
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);

            for(Session session1 : sessions.getSessions())
            {
                if(session.equals(session1.getSessionId()))
                {
                    session1.setBrandId(brand);
                    userStorageService.saveSessions(sessions, userId);
                    return true;
                }
            }
        } catch (JsonProcessingException e) {
            logger.error("Error reading SessionList!", e);
        }
        return false;
    }

    public String getBrand(String userId, String session){
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);

            for(Session session1 : sessions.getSessions())
            {
                if(session.equals(session1.getSessionId()))
                {
                    return session1.getBrandId();

                }
            }
        } catch (JsonProcessingException e) {
            logger.error("Error reading SessionList!", e);
        }
        return null;
    }

    public List<Session> getSessionList(String userId)
    {
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);
            return sessions.getSessions();
        } catch (JsonProcessingException e) {
            logger.error("Error reading SessionList!", e);
            return null;
        }
    }

    public boolean removeSession(String userId, String sessionId){
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);
            List<Session> savedSessions = new ArrayList<>();

            for(Session session : sessions.getSessions())
            {
                if(!sessionId.equals(session.getSessionId()))
                    savedSessions.add(session);
            }
            sessions.setSessions(savedSessions);
            userStorageService.saveSessions(sessions, userId);
            return true;
        } catch (JsonProcessingException e) {
            logger.error("Error reading SessionList!", e);
            return false;
        }
    }

    public boolean isValidSession(String userId, String app, String sessionId)
    {
        try
        {
            SessionList sessions = userStorageService.retrieveSessions(userId);
            return sessions.isValidSession(sessionId, appAgnostic ? null : app);
        }catch(Exception e)
        {
            logger.error("Error reading SessionList!", e);
            return false;
        }
    }
}
