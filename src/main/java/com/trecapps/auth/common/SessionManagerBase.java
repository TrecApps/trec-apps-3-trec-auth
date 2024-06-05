package com.trecapps.auth.common;

import com.trecapps.auth.common.models.SessionApp;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.SessionV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.OffsetDateTime;
import java.util.List;

public abstract class SessionManagerBase {
    // Whether we care what app the session belongs to
    protected boolean appAgnostic;


    final String AlphaNumericString = "ABCDEFGHIJ"
            + "0123456789"
            + "abcdefghij";

    final int RANDOM_STRING_LENGTH = 6;

    protected Logger logger = LoggerFactory.getLogger(SessionManagerBase.class);

    protected SessionManagerBase(boolean aa){
        this.appAgnostic = aa;
    }

    protected String getDeviceInfo(String agent)
    {
        if(agent == null)
            return null;
        StringBuilder ret = new StringBuilder();
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

            String[] segments = systemAgent.split(";");

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

    private String generateRandomString()
    {
        StringBuilder sb = new StringBuilder();
        for(int c = 0; c < RANDOM_STRING_LENGTH; c++)
        {
            int ch = (int) (Math.random() * AlphaNumericString.length());
            sb.append(AlphaNumericString.charAt(ch));
        }
        return sb.toString();
    }

    public SessionV2 prepareNewSession(SessionListV2 sessionList, String deviceInfo, String appId, OffsetDateTime expiration){
        SessionV2 ret = new SessionV2();
        ret.setExpiration(expiration);
        ret.setDeviceInfo(deviceInfo);
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp(appId);
        ret.getApps().add(sessionApp);

        List<String> ids = sessionList.getSessionIdList();

        String sessionId = null;
        do {
            sessionId = generateRandomString();
        } while(ids.contains(sessionId));

        ret.setDeviceId(sessionId);
        sessionList.getSessions().add(ret);
        return ret;
    }

    public void setApp(SessionListV2 sessionList, String sessionId, String app, String brand) {
        SessionV2 session = sessionList.getSessionById(sessionId);

        session.setApp(app, brand);
    }
}
