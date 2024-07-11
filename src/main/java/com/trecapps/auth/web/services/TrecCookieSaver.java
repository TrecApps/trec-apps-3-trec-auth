package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.common.models.*;

import java.util.List;
import java.util.Optional;

public class TrecCookieSaver {

    protected V2SessionManager sessionManager;
    protected JwtTokenService tokenService;
    protected IUserStorageService userStorageService;

    protected String app;

    protected TrecCookieSaver(
            V2SessionManager sessionManager1,
            JwtTokenService tokenService1,
            IUserStorageService userStorageService1,
            String app1){
        sessionManager = sessionManager1;
        tokenService = tokenService1;
        userStorageService = userStorageService1;
        app = app1;
    }

    protected LoginToken getLoginTokens(TrecAuthentication authentication, String client)
    {
        TokenTime time = null;

        List<SessionV2> sessionList = sessionManager.getSessionList(authentication.getAccount().getId());

        for(SessionV2 s: sessionList){
            if(authentication.getSessionId().equals(s.getDeviceId())){
                TcBrands brands = this.getBrand(s, authentication.getAccount().getId());

                time = tokenService.generateToken(authentication.getAccount(), client, brands, s.getDeviceId(), s.getExpiration() != null, app);
                break;
            }
        }

        if(time == null){
            time = sessionManager.addSession(app, authentication.getAccount().getId(), client, false);
        }



        LoginToken login = authentication.getLoginToken();
        if(login == null){

            if(time == null)
                return null;

            login = new LoginToken();
            authentication.setLoginToken(login);
        }
        login.setToken_type("User");
        login.setAccess_token(time.getToken());

        login.setRefresh_token(tokenService.generateRefreshToken(authentication.getAccount(), time.getSession()));
        return login;
    }

    protected void prepLoginTokens(TrecAuthentication authentication, String client)  {

        LoginToken token = authentication.getLoginToken();
        if(token == null)
        {
            token = getLoginTokens(authentication, client);
            authentication.setLoginToken(token);
        }


    }

    TcBrands getBrand(SessionV2 s, String userId){
        String brandId = s.getBrandByApp(app);
        if(brandId == null)
            return null;
        Optional<TcBrands> oRet = userStorageService.getBrandById(brandId);
        if(oRet.isPresent())
        {
            TcBrands ret = oRet.get();
            if(!ret.getOwners().contains(userId))
            {
                // To-Do: RED ALERT! Alert staff somehow
                return null;
            }

            return ret;
        }
        return null;

    }
}
