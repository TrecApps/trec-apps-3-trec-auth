package com.trecapps.auth.common.models;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class SessionListV2 {

    List<SessionV2> sessions = new ArrayList<>();

    public List<String> getSessionIdList(){
        return sessions.stream().map((SessionV2 session) -> session.deviceId).toList();
    }

    public SessionV2 getSessionById(String sessionId) {
        for(SessionV2 session: sessions){
            if(session.getDeviceId().equals(sessionId))
                return session;
        }
        return null;
    }

    public void prep(){
        for(SessionV2 session: sessions) {
            session.prep();
        }
    }
}
