package com.trecapps.auth.common.models;

import lombok.Data;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
public class SessionV2 {

    String deviceId;
    String deviceInfo;
    OffsetDateTime expiration;
    String expirationStr;
    List<SessionApp> apps = new ArrayList<>();
    List<String> blockedApps = new ArrayList<>();

    public boolean isExpired() {
        return expiration != null && expiration.isBefore(OffsetDateTime.now());
    }

    public void setApp(String app, String brand){
        setApp(app, brand, true);
    }

    public void setApp(String app, String brand, boolean doUpdate) {
        for(SessionApp sessionApp: apps){
            if(sessionApp.getApp().equals(app)) {
                if(doUpdate)
                    sessionApp.setBrandId(brand);
                return;
            }
        }

        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp(app);
        sessionApp.setBrandId(brand);
        apps.add(sessionApp);
    }

    public SessionApp getApp(String app){
        for(SessionApp sessionApp: apps){
            if(sessionApp.getApp().equals(app)) {
                return sessionApp;
            }
        }
        return null;
    }

    public String getBrandByApp(String app){
        for(SessionApp sessionApp: apps){
            if(sessionApp.getApp().equals(app))
                return sessionApp.getBrandId();
        }
        return null;
    }

    public void prep(){
        if(expiration != null)
            expirationStr = expiration.toString();
    }
}
