package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

public class TrecCookieSaverAsync {

    protected V2SessionManagerAsync sessionManager;
    protected JwtTokenServiceAsync tokenService;
    protected IUserStorageServiceAsync userStorageService;

    protected String app;

    protected TrecCookieSaverAsync(
            V2SessionManagerAsync sessionManager1,
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
                .map((List<SessionV2> sessionList) -> {
                    Optional<SessionV2> ret = Optional.empty();
                    for(SessionV2 s: sessionList) {
                        if (authentication.getSessionId().equals(s.getDeviceId()))
                            return Optional.of(s);
                    }
                    return ret;
                })
                .flatMap((Optional<SessionV2> sOpt) -> {
                    return sOpt.map(sessionV2 -> this.getBrand(sessionV2, authentication.getAccount().getId())
                            .map((Optional<TcBrands> brands) -> {
                                SessionV2 s = sessionV2;
                                TokenOptions options = new TokenOptions();
                                options.setSession(s.getDeviceId());
                                options.setExpires(s.getExpiration() != null);
                                return tokenService.generateToken(authentication.getAccount(), client, brands.orElse(null), app, options);
                            }).flatMap(m -> m)).orElseGet(() -> Mono.just(Optional.of(TokenTime.getInvalidInstance())));
                })
                .flatMap((Optional<TokenTime> tokenTime) -> {
                    if(tokenTime.isEmpty() || !tokenTime.get().isValid())
                        return sessionManager.addSession(app, authentication.getAccount().getId(), client, false);
                    return Mono.just(tokenTime.get());
                })
                .map((TokenTime tokenTime) -> {

                    LoginToken login = authentication.getLoginToken();
                    if(login == null){
                        login = new LoginToken();
                        authentication.setLoginToken(login);
                    }
                    login.setToken_type("User");
                    login.setAccess_token(tokenTime.getToken());

                    login.setRefresh_token(tokenService.generateRefreshToken(authentication.getAccount(), tokenTime.getSession()));
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

    Mono<Optional<TcBrands>> getBrand(SessionV2 s, String userId){
        if(s == null)
            return Mono.just(Optional.empty());
        String brandId = s.getBrandByApp(app);
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
