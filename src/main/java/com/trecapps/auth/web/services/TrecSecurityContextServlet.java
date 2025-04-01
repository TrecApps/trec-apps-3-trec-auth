package com.trecapps.auth.web.services;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.common.ISecurityAlertHandler;
import com.trecapps.auth.common.models.*;
import lombok.SneakyThrows;
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

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Component
public class TrecSecurityContextServlet extends TrecCookieSaver implements SecurityContextRepository  {

    ISecurityAlertHandler alertHandler;

    String cookieName;

    String cookieApp;

    String domain;

    boolean logLocal;

    boolean isLocal(String address) {
        return address.contains("localhost") || address.contains("127.0.0.1");
    }

    // endpoints that must not require MFA, likely because they help with getting MFA verified
    final List<String> mfaEndpointExceptions;

    @Autowired
    public TrecSecurityContextServlet(
            JwtTokenService jwtService,
            V2SessionManager sessionManager,
            IUserStorageService userStorageService,
            @Autowired(required = false) ISecurityAlertHandler alertHandler,
            @Value("${trecauth.app}") String app,
            @Value("${trecauth.refresh.cookie-name:#{NULL}}") String cookieName,
            @Value("${trecauth.refresh.app:#{NULL}}") String cookieApp,
            @Value("${trecauth.refresh.domain:#{NULL}}") String domain,
            @Value("${trecauth.flag-local:false}") boolean flagLocal,
            @Value("${trecauth.mfa.endpoint.exceptions:#{NULL}}") String exceptedEndpoints
    )
    {
        super(sessionManager, jwtService, userStorageService, app);
        this.domain = domain;
        this.cookieName = cookieName;
        this.cookieApp = cookieApp;
        this.alertHandler = alertHandler;
        this.logLocal = flagLocal;

        if(exceptedEndpoints == null)
            this.mfaEndpointExceptions = List.of();
        else {
            String[] endpoints = exceptedEndpoints.split(";");
            mfaEndpointExceptions = List.of(endpoints);
        }
    }

    Logger logger = LoggerFactory.getLogger(TrecSecurityContextServlet.class);

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {

        HttpServletRequest req = requestResponseHolder.getRequest();
        HttpServletResponse res = requestResponseHolder.getResponse();

        if(cookieApp != null && req.getRequestURI().endsWith("/refresh_token"))
            return getContextFromCookie(res, req);

        return getContextFromHeader(res, req);

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
                logger.debug("Setting Cookie domain to {}", domain);
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
            ret = getContextFromCookie(null, req);
        else
            ret = getContextFromHeader(null, req);

        return ret != null;
    }

    @SneakyThrows
    SecurityContext getContextFromCookie(HttpServletResponse response, HttpServletRequest request){
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

                JwtKeyArray.DecodedHolder decode = tokenService.decodeToken(data);
                if(decode.getDecodedJwt().isEmpty()) {
                    String address = Objects.requireNonNull(request.getRemoteAddr());
                    if(!isLocal(address) || logLocal)
                        logger.warn("Null Decode token detected from Cookie! Request Path: {} ; IP Address: {}", request.getContextPath(), request.getRemoteAddr());
                    return context;
                }
                if(decode.isKeyOutdated() && response != null)
                    response.addHeader("Update-Token", "true");

                TrecAuthentication acc = tokenService.verifyToken(decode.getDecodedJwt().get(), new TokenFlags());
                if(acc == null) {
                    logger.info("Null Account from Cookie detected!");
                    if(alertHandler != null){
                        alertHandler.alertNullAccount(
                                request.getRemoteAddr(),
                                request.getContextPath(),
                                request.getQueryString(),
                                request.getMethod()
                        );
                    }
                    return context;
                }
                context.setAuthentication(acc);
                logger.debug("Set Authentication from Cookie");
                return context;
            }
        }

        logger.debug("Empty Context from Cookie!");

        return context;
    }

    boolean needsMfa(TcUser user, DecodedJWT jwt, String endpoint){
        Claim mfaClaim = jwt.getClaim("mfa");
        if(!mfaClaim.isMissing() && mfaClaim.asBoolean()) {
            // MFA is factored in, no need to prompt user
            // Go ahead and add the MFA_PROVIDED Authority while at it
            user.addAuthority("MFA_PROVIDED");

            return false;
        }

        if(this.mfaEndpointExceptions.contains(endpoint))
            return false;

        String jwtApp = jwt.getIssuer();
        if(jwtApp == null) throw new RuntimeException("'app' is a required field in the Authentication token!");

        if(user.getMfaMechanisms().isEmpty())
            return false;

        // MFA is not verified, need to see if required
        for (MfaReq mfaRequirement : user.getMfaRequirements()) {
            if(mfaRequirement.getApp().equals(jwtApp))
                return mfaRequirement.isRequireMfa();
        }

        return false;
    }

    @SneakyThrows
    SecurityContext getContextFromHeader(HttpServletResponse response, HttpServletRequest request)
    {
        // Get the token and try to generate an Account from it
        String auth = request.getHeader("Authorization");
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        TokenFlags tokenFlags = new TokenFlags();
        JwtKeyArray.DecodedHolder decode = tokenService.decodeToken(auth);
        if(decode.getDecodedJwt().isEmpty()) {
            String address = Objects.requireNonNull(request.getRemoteAddr());
            if(!isLocal(address) || logLocal)
                logger.warn("Null Decode token detected from Header! Request Path: {} ; IP Address: {}", request.getContextPath(), address);
            return context;
        }
        if(decode.isKeyOutdated() && response != null)
            response.addHeader("Update-Token", "true");
        TrecAuthentication acc = tokenService.verifyToken(decode.getDecodedJwt().get(), tokenFlags);

        if(acc == null) {
            if(alertHandler != null){
                alertHandler.alertNullAccount(
                        request.getRemoteAddr(),
                        request.getContextPath(),
                        request.getQueryString(),
                        request.getMethod()
                );
            }
            return context;
        }

        acc.setMfaBlock(needsMfa(acc.getUser(), decode.getDecodedJwt().get(), request.getRequestURI()));

        if(acc.isMfaBlock())
            return context;
        // Now that we have our account, get Session Information
        String sessionId = tokenService.getSessionId(auth);
        // Only authenticate if both the user, app, and session can be verified
        if(sessionId != null && sessionManager.isValidSession(acc.getUser().getId(), app, sessionId)) {
            logger.debug("Found Valid Session!");
            acc.setSessionId(sessionId);
            LoginToken token = new LoginToken();
            token.setAccess_token(auth);
            acc.setLoginToken(token);


            context.setAuthentication(acc);
        }

        TcUser tcUser = acc.getUser();

        if(tcUser.isEmailVerified())
            tcUser.addAuthority("EMAIL_VERIFIED");
        if(tcUser.isPhoneVerified())
            tcUser.addAuthority("PHONE_VERIFIED");

        for(String role : tcUser.getAuthRoles())
            tcUser.addAuthority(role);


        return context;
    }


}
