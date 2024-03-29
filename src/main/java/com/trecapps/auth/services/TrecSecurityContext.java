package com.trecapps.auth.services;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.LoginToken;
import com.trecapps.auth.models.TcUser;
import com.trecapps.auth.models.TokenFlags;
import com.trecapps.auth.models.TrecAuthentication;
import com.trecapps.auth.models.primary.TrecAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class TrecSecurityContext implements SecurityContextRepository {

    @Autowired
    JwtTokenService jwtService;
    @Autowired SessionManager sessionManager;

    @Autowired
    UserStorageService userStorageService;

    @Value("${trecauth.app}")
    String app;

    @Value("${trecauth.refresh.cookie-name:#{NULL}}")
    String cookieName;

    @Value("${trecauth.refresh.app:#{NULL}}")
    String cookieApp;

    Logger logger = LoggerFactory.getLogger(TrecSecurityContext.class);

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {

        HttpServletRequest req = requestResponseHolder.getRequest();

        if(cookieApp != null && req.getRequestURI().endsWith("/refresh_token"))
            return getContextFromCookie(req);

        return getContextFromHeader(req);

    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        Cookie cook = null;
        if(!(context.getAuthentication() instanceof TrecAuthentication trecAuth))
        {
            cook = new Cookie("TRECSESSION", null);
        }
        else
        {

            // Cookie will have been set by the endpoint!
            if(!trecAuth.isRegularSession())
                return;

            LoginToken token = trecAuth.getLoginToken();

//            cook = new Cookie("TRECSESSION", token == null ?
//                    jwtService.generateToken(trecAuth.getAccount(), request.getHeader("User-Agent"), null) : token.getAccess_token());

        }

        if(cook != null && cook.getValue() != null)
            response.addHeader("SetAuth", cook.getValue());

    }

    @Override
    public boolean containsContext(HttpServletRequest req) {

        SecurityContext ret = null;
        if(cookieApp != null && req.getRequestURI().endsWith("/refresh_token"))
            ret = getContextFromCookie(req);
        else
            ret = getContextFromHeader(req);

        return ret != null;
    }

    SecurityContext getContextFromCookie(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        if(cookies == null) {
            return context;
        }
        for(Cookie c: cookies)
        {
            String name = c.getName();
            if(name.equals(cookieName))
            {
                String data = c.getValue();

                DecodedJWT decode = jwtService.decodeToken(data);
                if(decode == null) {
                    logger.info("Null Decode token detected!");
                    return context;
                }
                TrecAccount acc = jwtService.verifyToken(decode, new TokenFlags());
                if(acc == null) {
                    logger.info("Null Account from Cookie detected!");
                    return context;
                }
                TrecAuthentication tAuth = new TrecAuthentication(acc);
                context.setAuthentication(tAuth);
                logger.info("Set Authentication from Cookie");
                return context;
            }
        }

        logger.info("Empty Context from Cookie!");

        return context;
    }


    SecurityContext getContextFromHeader(HttpServletRequest request)
    {
        // Get the token and try to generate an Account from it
        String auth = request.getHeader("Authorization");
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        TokenFlags tokenFlags = new TokenFlags();
        DecodedJWT decode = jwtService.decodeToken(auth);
        if(decode == null)
            return context;
        TrecAccount acc = jwtService.verifyToken(decode, tokenFlags);
        if(acc == null)
            return context;

        // Now that we have our account, get Session Information
        TrecAuthentication tAuth = new TrecAuthentication(acc);
        String sessionId = jwtService.getSessionId(auth);
        // Only authenticate if both the user, app, and session can be verified
        if(sessionId != null && sessionManager.isValidSession(acc.getId(), app, sessionId)) {
            logger.info("Found Valid Session!");
            tAuth.setSessionId(sessionId);
            LoginToken token = new LoginToken();
            token.setAccess_token(auth);
            tAuth.setLoginToken(token);

            tAuth.setBrandId(acc.getBrandId());

            context.setAuthentication(tAuth);
        }

        try {
            TcUser tcUser = userStorageService.retrieveUser(acc.getId());

            if(tcUser.isEmailVerified())
                acc.addAuthority("EMAIL_VERIFIED");
            if(tcUser.isPhoneVerified())
                acc.addAuthority("PHONE_VERIFIED");

            if(tokenFlags.getIsMfa())
                acc.addAuthority("MFA_PROVIDED");

            for(String role : tcUser.getAuthRoles())
                acc.addAuthority(role);
        } catch (NullPointerException | JsonProcessingException e) {
            e.printStackTrace();
        }

        return context;
    }

//    SecurityContext getContextFromCookie(HttpServletRequest request)
//    {
//        Cookie[] cookies = request.getCookies();
//        SecurityContext context = SecurityContextHolder.createEmptyContext();
//        if(cookies == null) {
//            return context;
//        }
//        for(Cookie c: cookies)
//        {
//            String name = c.getName();
//            if(name.equals("TRECSESSION"))
//            {
//                String data = c.getValue();
//                TrecAccount acc = jwtService.verifyToken(data);
//                if(acc == null)
//                    return context;
//
//                TrecAuthentication tAuth = new TrecAuthentication(acc);
//                context.setAuthentication(tAuth);
//                return context;
//            }
//        }
//
//        return context;
//    }

}
