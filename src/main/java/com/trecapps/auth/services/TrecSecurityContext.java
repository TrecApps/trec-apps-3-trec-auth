package com.trecapps.auth.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.LoginToken;
import com.trecapps.auth.models.TcUser;
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

    Logger logger = LoggerFactory.getLogger(TrecSecurityContext.class);

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {


        HttpServletRequest req = requestResponseHolder.getRequest();
        return getContextFromHeader(req);

    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        Cookie cook = null;
        if(!(context.getAuthentication() instanceof TrecAuthentication))
        {
            cook = new Cookie("TRECSESSION", null);
        }
        else
        {
            TrecAuthentication trecAuth = (TrecAuthentication) context.getAuthentication();

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
    public boolean containsContext(HttpServletRequest request) {
        return getContextFromHeader(request) != null;
    }

    SecurityContext getContextFromHeader(HttpServletRequest request)
    {
        // Get the token and try to generate an Account from it
        String auth = request.getHeader("Authorization");
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        TrecAccount acc = jwtService.verifyToken(auth);
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
