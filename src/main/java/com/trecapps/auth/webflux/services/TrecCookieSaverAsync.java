package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

public class TrecCookieSaverAsync {

    protected SessionManagerAsync sessionManager;
    protected JwtTokenServiceAsync tokenService;
    protected IUserStorageServiceAsync userStorageService;

    protected String app;

    protected TrecCookieSaverAsync(
            SessionManagerAsync sessionManager1,
            JwtTokenServiceAsync tokenService1,
            IUserStorageServiceAsync userStorageService1,
            String app1){
        sessionManager = sessionManager1;
        tokenService = tokenService1;
        userStorageService = userStorageService1;
        app = app1;
    }

    protected Mono<Optional<LoginToken>> getLoginTokens(TrecAuthentication authentication, String client)
    {
        return sessionManager.getSessionList(authentication.getAccount().getId())
                .map((List<Session> sessionList) -> {
                    for(Session s: sessionList)
                        if(app.equals(s.getAppId()))
                            return s;
                    return null;
                })
                .flatMap((Session s) -> {
                    if(s == null)
                        return Mono.just(Optional.of(TokenTime.getInvalidInstance()));
                    return this.getBrand(s, authentication.getAccount().getId())
                            .map((Optional<TcBrands> brands) -> {
                                String brandStr = null;
                                if(brands.isPresent())
                                    return tokenService.generateToken(authentication.getAccount(), client, brands.get(), s.getSessionId(), s.getExpiration() != null, app);
                                return tokenService.generateToken(authentication.getAccount(), client, null, s.getSessionId(), s.getExpiration() != null, app);
                            }).flatMap(m -> m);
                })
                .flatMap((Optional<TokenTime> tokenTime) -> {
                    if(tokenTime.isEmpty() || !tokenTime.get().isValid())
                        return sessionManager.addSession(app, authentication.getAccount().getId(), client, false);
                    return Mono.just(tokenTime);
                })
                .map((Optional<TokenTime> oTokenTime) -> {
                    if(oTokenTime.isEmpty())
                        return null;
                    LoginToken login = authentication.getLoginToken();
                    if(login == null){
                        login = new LoginToken();
                        authentication.setLoginToken(login);
                    }
                    login.setToken_type("User");
                    login.setAccess_token(oTokenTime.get().getToken());

                    login.setRefresh_token(tokenService.generateRefreshToken(authentication.getAccount()));
                    return login;
                })
                .map((loginToken -> loginToken == null ? Optional.empty() : Optional.of(loginToken)));
    }

    protected Mono<Optional<LoginToken>> prepLoginTokens(TrecAuthentication authentication, String client)  {

        LoginToken token = authentication.getLoginToken();
        if(token != null)
            return Mono.just(Optional.of(token));
        return getLoginTokens(authentication, client).doOnNext((Optional<LoginToken> oToken) -> {
            oToken.ifPresent(authentication::setLoginToken);
        });
    }

    Mono<Optional<TcBrands>> getBrand(Session s, String userId){
        if(s == null)
            return Mono.just(Optional.empty());
        String brandId = s.getBrandId();
        if(brandId == null)
            return Mono.just(Optional.empty());

        return userStorageService.getBrandById(brandId)
                .map((Optional<TcBrands> oBrands) -> {
                    if(oBrands.isPresent()){
                        TcBrands ret = oBrands.get();
                        if(!ret.getOwners().contains(userId))
                        {
                            // To-Do: RED ALERT alert staff somehow
                            return Optional.empty();
                        }
                    }
                    return oBrands;
                });
    }
}
