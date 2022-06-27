package com.trecapps.auth.models;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Transient;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SessionList {

    @Transient
    final String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789"
            + "abcdefghijklmnopqrstuvxyz";
    @Transient
    final int RANDOM_STRING_LENGTH = 6;

    final static int MAX_SESSION_COUNT = 30;

    boolean notExpired(OffsetDateTime dateTime) {
        return OffsetDateTime.now().isBefore(dateTime);


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

    List<Session> sessions;

    public String addNewSession(String app, OffsetDateTime expiration)
    {
        List<String> currentIds = new ArrayList<>();
        for(Session session: sessions){
            currentIds.add(session.sessionId);
        }
        String newId;

        for(int rust = 0; rust < MAX_SESSION_COUNT; rust++)
        {
            newId = generateRandomString();
            if(!currentIds.contains(newId))
            {
                sessions.add(new Session(newId,app, expiration));
                return newId;
            }
        }
        return null;
    }

    public boolean isValidSession(String id, String app)
    {
        for(Session session: sessions)
        {
            if(session.sessionId.equals(id))
            {
                return app.equals(session.appId) && (session.expiration == null ? true : notExpired(session.expiration));
            }
        }
        return false;
    }
}