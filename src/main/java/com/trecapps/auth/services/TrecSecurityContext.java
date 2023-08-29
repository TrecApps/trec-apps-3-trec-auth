package com.trecapps.auth.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.*;
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
import reactor.netty.http.Cookies;

import java.time.OffsetDateTime;

@Component
public class TrecSecurityContext implements SecurityContextRepository {

    @Autowired
    JwtTokenService jwtService;
    @Autowired SessionManager sessionManager;

    @Autowired
    UserStorageService userStorageService;

    @Value("${trecauth.app}")
    String app;

    // This will be the only endpoint where the authorization will be in the cookie
    @Value("${trecauth.refresh.endpoint:refresh_token}")
    String refreshEndpoint;

    @Value("${trecauth.refresh.app:TREC_APPS_REFRESH}")
    String refreshCookie;

    // Cookies should be sent only over HTTPS. However, on local this may not be an option
    @Value("${trecauth.refresh.on_local:false}")
    boolean onLocal;

    // if not local, needs to be set
    @Value("${trecauth.refresh.domain:null}")
    String domain;

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

    SecurityContext getContextForRefresh(HttpServletRequest request){
        String endpoint = request.getContextPath();

        // We only check the cookie when the user is refreshing the session.
        // Otherwise, use the Authorization header as normal
        if(!endpoint.endsWith(refreshEndpoint))
            return null;

        Cookie[] cooks = request.getCookies();
        Cookie cook = null;

        // Retrieve all cookies available to us. We only deal with cookies that are our own and are secure (or local)
        for (Cookie c: cooks) {
            if(c.getName().equals(refreshCookie) && c.isHttpOnly() &&
                    (onLocal || (domain.equals(c.getDomain()) && c.getSecure()))){
                cook = c;
                break;
            }
        }
        if(cook == null)
            return null;

        String val = cook.getValue();
        TokenTime tt =jwtService.generateNewTokenFromRefresh(val);
        if(tt == null)
            return null;

        TokenFlags tf = new TokenFlags();
        tf.setIsMfa(false);
        TrecAccount trecAccount = jwtService.verifyToken(tt.getToken(), tf);
        if(trecAccount == null)return null;

        TrecAuthentication tAuth = new TrecAuthentication(trecAccount);
        tAuth.setSessionId(tt.getSession());
        tAuth.setBrandId(trecAccount.getBrandId());
        LoginToken tok = new LoginToken();
        tok.setAccess_token(tt.getToken());
        tok.setRefresh_token(val);
        tok.setToken_type("User");
        OffsetDateTime expires = tt.getExpiration();
        if(expires != null)
            tok.setExpires_in(expires.getNano() - OffsetDateTime.now().getNano());
        tAuth.setLoginToken(tok);
        SecurityContext ret = SecurityContextHolder.createEmptyContext();
        ret.setAuthentication(tAuth);

        return ret;
    }

    SecurityContext getContextFromHeader(HttpServletRequest request)
    {
        // First Address Refresh attempt
        SecurityContext context = getContextForRefresh(request);
        if(context != null)
            return context;
        // Get the token and try to generate an Account from it
        String auth = request.getHeader("Authorization");
        context = SecurityContextHolder.createEmptyContext();

        TokenFlags tokenFlags = new TokenFlags();
        TrecAccount acc = jwtService.verifyToken(auth, tokenFlags);
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
