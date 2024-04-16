package com.trecapps.auth.services.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.*;

import java.util.List;

public class TrecCookieSaver {

    protected SessionManager sessionManager;
    protected JwtTokenService tokenService;
    protected UserStorageService userStorageService;

    protected String app;

    protected TrecCookieSaver(
            SessionManager sessionManager1,
            JwtTokenService tokenService1,
            UserStorageService userStorageService1,
            String app1){
        sessionManager = sessionManager1;
        tokenService = tokenService1;
        userStorageService = userStorageService1;
        app = app1;
    }


    protected void prepLoginTokens(TrecAuthentication authentication, String client)  {
        TokenTime time = null;

        List<Session> sessionList = sessionManager.getSessionList(authentication.getAccount().getId());

        for(Session s: sessionList){
            if(app.equals(s.getAppId())){
                TcBrands brands = this.getBrand(s, authentication.getAccount().getId());

                time = tokenService.generateToken(authentication.getAccount(), client, brands, s.getSessionId(), s.getExpiration() != null, app);
                break;
            }
        }

        if(time == null){
            time = sessionManager.addSession(app, authentication.getAccount().getId(), client, false);
        }



        LoginToken login = authentication.getLoginToken();
        if(login == null){

            if(time == null)
                return;

            login = new LoginToken();
            authentication.setLoginToken(login);
        }
        login.setToken_type("User");
        login.setAccess_token(time.getToken());

        login.setRefresh_token(tokenService.generateRefreshToken(authentication.getAccount()));

        authentication.setLoginToken(login);
    }

    TcBrands getBrand(Session s, String userId){
        try{
            String brandId = s.getBrandId();
            if(brandId == null)
                return null;
            TcBrands ret = userStorageService.retrieveBrand(brandId);
            if(ret != null)
            {
                if(!ret.getOwners().contains(userId))
                {
                    // To-Do: RED ALERT alert staff somehow
                    return null;
                }


            }
            return ret;
        } catch(JsonProcessingException e){
            // To-Do: Add event to indicate this had happened
            return null;
        }
    }
}
