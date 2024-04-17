package com.trecapps.auth.services.web;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.LoginToken;
import com.trecapps.auth.models.TcUser;
import com.trecapps.auth.models.TokenFlags;
import com.trecapps.auth.models.TrecAuthentication;
import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.services.core.SessionManager;
import com.trecapps.auth.services.core.JwtTokenService;
import com.trecapps.auth.services.core.TrecCookieSaver;
import com.trecapps.auth.services.core.UserStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.concurrent.TimeUnit;

@Component
public class TrecSecurityContextServlet extends TrecCookieSaver implements SecurityContextRepository  {

    String cookieName;


    String cookieApp;

    String domain;

    @Autowired
    public TrecSecurityContextServlet(
            JwtTokenService jwtService,
            SessionManager sessionManager,
            UserStorageService userStorageService,
            @Value("${trecauth.app}") String app,

            @Value("${trecauth.refresh.cookie-name:#{NULL}}")
            String cookieName,

            @Value("${trecauth.refresh.app:#{NULL}}")
            String cookieApp,
            @Value("${trecauth.refresh.domain:#{NULL}}")
            String domain)
    {
        super(sessionManager, jwtService, userStorageService, app);
        this.domain = domain;
        this.cookieName = cookieName;
        this.cookieApp = cookieApp;

    }

    Logger logger = LoggerFactory.getLogger(TrecSecurityContextServlet.class);

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {

        HttpServletRequest req = requestResponseHolder.getRequest();

        if(cookieApp != null && req.getRequestURI().endsWith("/refresh_token"))
            return getContextFromCookie(req);

        return getContextFromHeader(req);

    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = context.getAuthentication();
        if(!(auth instanceof TrecAuthentication trecAuthentication))
            return;

        if(trecAuthentication.isUseCookie())
        {
            this.prepLoginTokens(trecAuthentication, request.getHeader("User-Agent"));

            Cookie cook = new Cookie(cookieName, trecAuthentication.getLoginToken().getRefresh_token());
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

                DecodedJWT decode = tokenService.decodeToken(data);
                if(decode == null) {
                    logger.info("Null Decode token detected!");
                    return context;
                }
                TrecAuthentication acc = tokenService.verifyToken(decode, new TokenFlags());
                if(acc == null) {
                    logger.info("Null Account from Cookie detected!");
                    return context;
                }
                context.setAuthentication(acc);
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
        DecodedJWT decode = tokenService.decodeToken(auth);
        if(decode == null)
            return context;
        TrecAuthentication acc = tokenService.verifyToken(decode, tokenFlags);
        if(acc == null)
            return context;

        // Now that we have our account, get Session Information
        String sessionId = tokenService.getSessionId(auth);
        // Only authenticate if both the user, app, and session can be verified
        if(sessionId != null && sessionManager.isValidSession(acc.getUser().getId(), app, sessionId)) {
            logger.info("Found Valid Session!");
            acc.setSessionId(sessionId);
            LoginToken token = new LoginToken();
            token.setAccess_token(auth);
            acc.setLoginToken(token);

            acc.setBrandId(acc.getBrandId());

            context.setAuthentication(acc);
        }

        try {
            TcUser tcUser = acc.getUser();

            if(tcUser.isEmailVerified())
                tcUser.addAuthority("EMAIL_VERIFIED");
            if(tcUser.isPhoneVerified())
                tcUser.addAuthority("PHONE_VERIFIED");

            if(tokenFlags.getIsMfa())
                tcUser.addAuthority("MFA_PROVIDED");

            for(String role : tcUser.getAuthRoles())
                tcUser.addAuthority(role);
        } catch (NullPointerException e) {
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
