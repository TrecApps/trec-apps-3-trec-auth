package com.trecapps.auth.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.*;
import com.trecapps.auth.services.JwtTokenService;
import com.trecapps.auth.services.SessionManager;
import com.trecapps.auth.services.UserStorageService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/refresh_token")
@ConditionalOnProperty(prefix = "trecauth", name="use-cookie", havingValue = "true")
public class CookieController {

    @Autowired
    CookieBase cookieBase;

    @Autowired
    SessionManager sessionManager;

    @Autowired
    JwtTokenService tokenService;

    @Autowired
    UserStorageService userStorageService;

    @Value("${trecauth.refresh.app}")
    String cookieAppName;

    @Value("${trecauth.app}")
    String app;

    @GetMapping
    public ResponseEntity<LoginToken> checkRefresh(HttpServletRequest req,HttpServletResponse response){
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context == null ? null : context.getAuthentication();

        if(authentication instanceof TrecAuthentication){
            TrecAuthentication tAuth = (TrecAuthentication) authentication;

            prepLoginTokens(tAuth, req.getHeader("User-Agent"));

            cookieBase.SetCookie(response, tAuth.getLoginToken().getRefresh_token());
            return new ResponseEntity<>(tAuth.getLoginToken(), HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }


    void prepLoginTokens(TrecAuthentication authentication, String client)  {
        TokenTime time = null;

        List<Session> sessionList = sessionManager.getSessionList(authentication.getAccount().getId());

         for(Session s: sessionList){
            if(app.equals(s.getAppId())){
                TcBrands brands = this.getBrand(s, authentication.getAccount().getId());

                time = tokenService.generateToken(authentication.getAccount(), client, brands, s.getSessionId(), s.getExpiration() != null);
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
