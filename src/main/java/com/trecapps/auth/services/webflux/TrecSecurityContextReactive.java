package com.trecapps.auth.services.webflux;


import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.models.LoginToken;
import com.trecapps.auth.models.TcUser;
import com.trecapps.auth.models.TokenFlags;
import com.trecapps.auth.models.TrecAuthentication;
import com.trecapps.auth.services.core.JwtTokenService;
import com.trecapps.auth.services.core.SessionManager;
import com.trecapps.auth.services.core.TrecCookieSaver;
import com.trecapps.auth.services.core.UserStorageService;
import com.trecapps.auth.services.web.TrecSecurityContextServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.netty.http.server.HttpServerRequest;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class TrecSecurityContextReactive extends TrecCookieSaver implements ServerSecurityContextRepository {

    Logger logger = LoggerFactory.getLogger(TrecSecurityContextReactive.class);

    String cookieApp;

    String cookieName;

    String domain;

    @Autowired
    public TrecSecurityContextReactive(
            JwtTokenService tokenService,
            SessionManager sessionManager,
            UserStorageService userStorageService1,
            @Value("${trecauth.app}") String app,
            @Value("${trecauth.refresh.domain:#{NULL}}") String domain,
            @Value("${trecauth.refresh.app:#{NULL}}") String cookieApp,
            @Value("${trecauth.refresh.cookie-name:#{NULL}}") String cookieName
    )
    {
        super(sessionManager,tokenService, userStorageService1, app);
        this.domain = domain;
        this.cookieApp = cookieApp;
        this.cookieName = cookieName;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {

        Authentication auth = context.getAuthentication();
        if(!(auth instanceof TrecAuthentication trecAuthentication))
            return Mono.empty();

        this.prepLoginTokens(trecAuthentication, exchange
                .getRequest()
                .getHeaders()
                .getFirst("User-Agent"));


        ServerHttpResponse response = exchange.getResponse();
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(cookieName)
            .secure(true)
            .path("/")
            .httpOnly(true)
            .maxAge(TimeUnit.DAYS.toSeconds(7))
            .value(trecAuthentication.getLoginToken().getRefresh_token());

        if(domain != null)
            cookieBuilder = cookieBuilder.domain(domain);

        response.addCookie(cookieBuilder.build());

        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        ServerHttpRequest req = exchange.getRequest();

        if(cookieApp != null && req.getPath().contextPath().value().endsWith("/refresh_token"))
            return getContectFromCookie(req);
        return getContextFromHeader(req);
    }

    void handleSecurityDecoding(DecodedJWT decode, SecurityContext context)
    {
        TrecAuthentication acc = tokenService.verifyToken(decode, new TokenFlags());
        if(acc == null)
        {
            logger.info("Null Account from Cookie detected!");
            return;
        }
        context.setAuthentication(acc);
        logger.info("Set Authentication from Cookie");
    }


    Mono<SecurityContext> getContectFromCookie(ServerHttpRequest request) {
        return Mono.just(SecurityContextHolder.createEmptyContext())
                .doOnNext((SecurityContext context) -> {

                    MultiValueMap<String, HttpCookie> cookies = request.getCookies();
                    HttpCookie cookie = cookies.getFirst(cookieName);
                    if(cookie != null)
                    {
                        DecodedJWT decode = tokenService.decodeToken(cookie.getValue());
                        if(decode == null) {
                            logger.info("Null Decode token detected!");
                        }
                        else
                        {
                            handleSecurityDecoding(decode, context);
                        }
                    }
                });


    }

    Mono<SecurityContext> getContextFromHeader(ServerHttpRequest request) {
        return Mono.just(SecurityContextHolder.createEmptyContext())
                .doOnNext((SecurityContext context) -> {
                    HttpHeaders headers = request.getHeaders();
                    String auth = headers.getFirst("Authorization");
                    DecodedJWT decode = tokenService.decodeToken(auth);
                    if(decode == null) {
                        logger.info("Null Decode token detected!");
                    }
                    else
                    {
                        TokenFlags tokenFlags = new TokenFlags();
                        String sessionId = tokenService.getSessionId(auth);
                        TrecAuthentication acc = tokenService.verifyToken(decode, tokenFlags);


                        if(sessionId != null && sessionManager.isValidSession(acc.getUser().getId(), app, sessionId)) {
                            logger.info("Found Valid Session!");
                            acc.setSessionId(sessionId);
                            LoginToken token = new LoginToken();
                            token.setAccess_token(auth);
                            acc.setLoginToken(token);

                            acc.setBrandId(acc.getBrandId());

                            context.setAuthentication(acc);
                        }
                    }
                })
                .doOnNext((SecurityContext context) -> {
                    Authentication auth = context.getAuthentication();
                    if(auth instanceof TrecAuthentication trecAuthentication)
                    {
                        TcUser tcUser = trecAuthentication.getUser();

                        if(tcUser.isEmailVerified())
                            tcUser.addAuthority("EMAIL_VERIFIED");
                        if(tcUser.isPhoneVerified())
                            tcUser.addAuthority("PHONE_VERIFIED");

//                        if(tokenFlags.getIsMfa())
//                            tcUser.addAuthority("MFA_PROVIDED");

                        for(String role : tcUser.getAuthRoles())
                            tcUser.addAuthority(role);
                    }
                });
    }
}
