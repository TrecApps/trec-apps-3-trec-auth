package com.trecapps.auth.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.Session;
import com.trecapps.auth.models.SessionList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SessionManager {

    @Autowired
    UserStorageService userStorageService;

    Logger logger = LoggerFactory.getLogger(SessionManager.class);

    public String addSession(String app, String userId){
        try {
            SessionList sessions = userStorageService.retrieveSessions(userId);

            String ret = sessions.addNewSession(app, null);
            userStorageService.saveSessions(sessions, userId);
            return ret;
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
            return sessions.isValidSession(sessionId, app);
        }catch(Exception e)
        {
            logger.error("Error reading SessionList!", e);
            return false;
        }
    }
}
