package com.trecapps.auth.common;

import com.trecapps.auth.web.services.SessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SessionManagerBase {
    // Whether we care what app the session belongs to
    protected boolean appAgnostic;

    protected Logger logger = LoggerFactory.getLogger(SessionManagerBase.class);

    protected SessionManagerBase(boolean aa){
        this.appAgnostic = aa;
    }

    protected String getDeviceInfo(String agent)
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
}
