package com.trecapps.auth.webflux.controllers;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.webflux.services.JwtTokenServiceAsync;
import com.trecapps.auth.webflux.services.V2SessionManagerAsync;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

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
    JwtTokenServiceAsync tokenService;
    @Autowired
    V2SessionManagerAsync sessionManager;

    public String getCookieAppName(){
        return this.appName;
    }

    public String getCookieName(){
        return this.cookieName;
    }

    public String getDomain(){
        return this.domain;
    }

    public void SetCookie(ServerHttpResponse response, String refreshToken){
        ResponseCookie.ResponseCookieBuilder cookBuilder = ResponseCookie.from(this.cookieName, refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge((int)TimeUnit.DAYS.toSeconds(7L));
        if(this.domain != null)cookBuilder = cookBuilder.domain(this.domain);

        response.addCookie(cookBuilder.build());
    }

    public void RemoveCookie(ServerHttpResponse response, ServerHttpRequest request, String userId){
        HttpCookie cookie = request.getCookies().getFirst(cookieName);
        if(cookie != null)
            clearSessions(cookie.getValue(), userId);

        ResponseCookie.ResponseCookieBuilder cookBuilder = ResponseCookie.from(this.cookieName, "")
                .path("/")
                .maxAge(0);
        response.addCookie(cookBuilder.build());
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
