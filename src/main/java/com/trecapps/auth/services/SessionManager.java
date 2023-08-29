package com.trecapps.auth.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.Session;
import com.trecapps.auth.models.SessionList;
import com.trecapps.auth.models.TokenTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class SessionManager {

    @Autowired
    UserStorageService userStorageService;

    Logger logger = LoggerFactory.getLogger(SessionManager.class);

    private String getDeviceInfo(String agent)
    {
        if(agent == null)
            return null;
        StringBuilder ret = new StringBuilder("");
        if(agent.contains("Edg"))
            ret.append("Broswer: Microsoft Edge");
        else if(agent.contains("Chrome"))
            ret.append("Browser: Google Chrome");
        else if(agent.contains("OPR"))
            ret.append("Browser: Opera");
        else if(agent.contains("Safari"))
            ret.append("Browser: Safari");
        else if(agent.contains("Firefox"))
            ret.append("Browser: Mozilla FireFox");
        else if(agent.contains("Web-Tours"))
            ret.append("Browser: Trec-Apps Web-Tours");

        int startParenth = agent.indexOf('('), endParenth = agent.indexOf(')');

        ret.append(' ');

        if(startParenth != -1 && endParenth > startParenth)
        {
            String systemAgent = agent.substring(startParenth + 1, endParenth);

            String[] segments = systemAgent.split("[;]");

            // Check for Windows
            if(segments.length > 1 && segments[0].contains("Windows"))
            {
                ret.append("OS: ").append(segments[0].trim())
                        .append(" System: ").append(segments[1].trim());
            }

            // Check for Mac
            if(segments.length > 1 && segments[0].contains("Macintosh"))
            {
                ret.append("Computer: ").append(segments[0].trim())
                        .append(" System: ").append(segments[1].trim());
            }

            if(segments.length > 1 && segments[1].contains("Linux"))
            {
                ret.append("Computer: ").append(segments[1].trim())
                        .append(" System: ").append(segments[0].trim());
            }
        }

        ret.append(" ");
        if(agent.contains("Mobile"))
            ret.append("Mobile");

        if(!agent.contains(" "))
            ret.append("Tool: ").append(agent);

        return ret.toString();
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
