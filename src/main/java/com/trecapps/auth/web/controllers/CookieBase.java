package com.trecapps.auth.web.controllers;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.common.models.SessionV2;
import com.trecapps.auth.web.services.JwtTokenService;
import com.trecapps.auth.web.services.V2SessionManager;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@ConditionalOnProperty(prefix = "trecauth", name="use-cookie", havingValue = "true")
public class CookieBase {

    Logger logger = LoggerFactory.getLogger(CookieBase.class);

    @Value("${trecauth.refresh.cookie-name:TREC_APPS_REFRESH}")
    String cookieName;

    @Value("${trecauth.refresh.domain}")
    String domain;

    @Value("${trecauth.refresh.app}")
    String appName;

    @Autowired
    JwtTokenService tokenService;
    @Autowired
    V2SessionManager sessionManager;

    public String getCookieAppName(){
        return this.appName;
    }

    public String getCookieName(){
        return this.cookieName;
    }

    public String getDomain(){
        return this.domain;
    }

    public void SetCookie(HttpServletResponse response, String refreshToken){
        Cookie cook = new Cookie(cookieName, refreshToken);
        cook.setHttpOnly(true);
        cook.setPath("/");
        if(domain != null) {
            logger.info("Setting Cookie domain to {}", domain);
            cook.setDomain(domain);
        }
        cook.setSecure(true);

        cook.setMaxAge((int) TimeUnit.DAYS.toSeconds(7));

        response.addCookie(cook);
    }

    public void RemoveCookie(HttpServletRequest request, HttpServletResponse response, String userId){
        for(Cookie cook : request.getCookies())
        {
            if(cook.getName().equals(cookieName))
            {
                clearSessions(cook.getValue(), userId);

                cook.setValue("");
                cook.setPath("/");
                cook.setMaxAge(0);
                response.addCookie(cook);
                return;
            }
        }
    }

    public void clearSessions(String value, String userId){
        DecodedJWT decodedJWT = tokenService.decodeToken(value);
        if(decodedJWT == null)return;

        Map<String, String> sessionList = tokenService.claims(decodedJWT);

        sessionList.forEach((String _app, String s) -> sessionManager.removeSession(userId, s));

    }

    public void assertAppAdded(String userId, String sessionId, String brandId){
        sessionManager.setBrand(userId, sessionId, brandId, appName, false);
    }
}
