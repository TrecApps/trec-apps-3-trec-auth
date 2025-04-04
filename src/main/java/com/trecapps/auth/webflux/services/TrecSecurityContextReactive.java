package com.trecapps.auth.webflux.services;


import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.common.ISecurityAlertHandler;
import com.trecapps.auth.common.models.*;
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

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class TrecSecurityContextReactive extends TrecCookieSaverAsync implements ServerSecurityContextRepository {

    Logger logger = LoggerFactory.getLogger(TrecSecurityContextReactive.class);

    String cookieApp;

    String cookieName;

    String domain;

    ISecurityAlertHandler alertHandler;

    boolean logLocal;

    boolean isLocal(String address) {
        return address.contains("localhost") || address.contains("127.0.0.1");
    }

    // endpoints that must not require MFA, likely because they help with getting MFA verified
    final List<String> mfaEndpointExceptions;

    @Autowired
    public TrecSecurityContextReactive(
            JwtTokenServiceAsync tokenService,
            V2SessionManagerAsync sessionManager,
            IUserStorageServiceAsync userStorageService1,
            @Autowired(required = false) ISecurityAlertHandler alertHandler,
            @Value("${trecauth.app}") String app,
            @Value("${trecauth.refresh.domain:#{NULL}}") String domain,
            @Value("${trecauth.refresh.app:#{NULL}}") String cookieApp,
            @Value("${trecauth.refresh.cookie-name:#{NULL}}") String cookieName,
            @Value("${trecauth.flag-local:false}") boolean flagLocal,
            @Value("${trecauth.mfa.endpoint.exceptions:#{NULL}}") String exceptedEndpoints
    )
    {
        super(sessionManager,tokenService, userStorageService1, app);
        this.alertHandler = alertHandler;
        this.domain = domain;
        this.cookieApp = cookieApp;
        this.cookieName = cookieName;
        this.logLocal = flagLocal;

        if(exceptedEndpoints == null)
            this.mfaEndpointExceptions = List.of();
        else {
            String[] endpoints = exceptedEndpoints.split(";");
            mfaEndpointExceptions = List.of(endpoints);
        }
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
        Mono<SecurityContext> ret;
        String path = req.getPath().value();
        if(cookieApp != null && path.endsWith("/refresh_token"))
            ret = getContextFromCookie(exchange.getResponse(), req);
        else
            ret = getContextFromHeader(req);
        return ret.doOnNext((SecurityContext context) -> {
            if(context.getAuthentication() == null)
                context.setAuthentication(new AnonymousAuthentication());
        });
    }

    Mono<SecurityContext> handleSecurityDecoding(DecodedJWT decode, SecurityContext context,ServerHttpRequest request)
    {
        return tokenService.verifyToken(decode, new TokenFlags())
                .map((Optional<TrecAuthentication> oTrecAuthentication) -> {
                    if(oTrecAuthentication.isEmpty())
                    {
                        logger.info("Null Account from Cookie detected!");
                        if(alertHandler != null) {
                            MultiValueMap<String, String> queryMap = request.getQueryParams();
                            StringBuilder queryStr = new StringBuilder();
                            
                            queryMap.forEach((String key, List<String> values) -> {
                                
                                for(String value: values){
                                    if(!queryStr.isEmpty())
                                        queryStr.append('&');
                                    queryStr.append(key).append('=').append(value);
                                }
                                
                            });
                            alertHandler.alertNullAccount(
                                    Objects.requireNonNull(request.getRemoteAddress()).toString(),
                                    request.getPath().toString(),
                                    queryStr.toString(),
                                    request.getMethod().name());
                        }
                    }
                    else context.setAuthentication(oTrecAuthentication.get());
                    return context;
                });
    }


    Mono<SecurityContext> getContextFromCookie(ServerHttpResponse response, ServerHttpRequest request) {
        return Mono.just(SecurityContextHolder.createEmptyContext())
                .flatMap((SecurityContext context) -> {

                    MultiValueMap<String, HttpCookie> cookies = request.getCookies();
                    HttpCookie cookie = cookies.getFirst(cookieName);
                    if(cookie != null)
                    {
                        JwtKeyArray.DecodedHolder decode = tokenService.decodeToken(cookie.getValue());
                        if(decode.getDecodedJwt().isEmpty()) {
                            String address = Objects.requireNonNull(request.getRemoteAddress()).toString();
                            if(!isLocal(address) || logLocal)
                                logger.info("Null Decode token detected in Cookie! request path: {} , IP Address: {}", request.getPath(), address);

                        }
                        else
                        {
                            if(decode.isKeyOutdated())
                                response.getHeaders().add("Update-Token", "true");
                            return handleSecurityDecoding(decode.getDecodedJwt().get(), context, request);
                        }
                    }
                    return Mono.just(context);
                });


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

    Mono<SecurityContext> getContextFromHeader(ServerHttpRequest request) {
        return Mono.just(SecurityContextHolder.createEmptyContext())
                .flatMap((SecurityContext context) -> {
                    HttpHeaders headers = request.getHeaders();
                    String auth = headers.getFirst("Authorization");
                    JwtKeyArray.DecodedHolder decode = tokenService.decodeToken(auth);
                    if(decode.getDecodedJwt().isEmpty()) {
                        String address = Objects.requireNonNull(request.getRemoteAddress()).toString();
                        if(!isLocal(address) || logLocal)
                            logger.info("Null Decode token detected in Auth Header! request path: {} , IP Address: {}", request.getPath(), address);
                        return Mono.just(context);
                    }
                    else
                    {
                        TokenFlags tokenFlags = new TokenFlags();
                        tokenFlags.setTokenOld(decode.isKeyOutdated());
                        String sessionId = tokenService.getSessionId(auth);
                        return tokenService.verifyToken(decode.getDecodedJwt().get(), tokenFlags)
                                .flatMap((Optional<TrecAuthentication> oAuth) -> {
                                    if(oAuth.isPresent() && sessionId != null)
                                    {
                                        TrecAuthentication acc = oAuth.get();
                                        return sessionManager.isValidSession(acc.getUser().getId(), app, sessionId)
                                                .map((Boolean isValidSession) -> {
                                                    if(isValidSession){

                                                        acc.setMfaBlock(needsMfa(acc.getUser(), decode.getDecodedJwt().get(), request.getPath().value()));

                                                        acc.setSessionId(sessionId);
                                                        LoginToken token = new LoginToken();
                                                        token.setAccess_token(auth);
                                                        acc.setLoginToken(token);

                                                        if(!acc.isMfaBlock())
                                                            context.setAuthentication(acc);
                                                    }
                                                    else {
                                                        logger.info("Session {} deemed invalid!", sessionId);
                                                    }
                                                    return context;
                                                });


                                    } else{
                                        logger.info("Not setting authentication due to sessionId {} and authorization {}", sessionId, oAuth.orElse(null));
                                    }
                                    return Mono.just(context);
                                });



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

                        for(String role : tcUser.getAuthRoles())
                            tcUser.addAuthority(role);
                    }
                });
    }
}
