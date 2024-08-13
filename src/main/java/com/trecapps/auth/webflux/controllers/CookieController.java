package com.trecapps.auth.webflux.controllers;

import com.trecapps.auth.common.models.LoginToken;
import com.trecapps.auth.common.models.MfaReq;
import com.trecapps.auth.common.models.TcUser;
import com.trecapps.auth.common.models.TrecAuthentication;
import com.trecapps.auth.webflux.services.IUserStorageServiceAsync;
import com.trecapps.auth.webflux.services.JwtTokenServiceAsync;
import com.trecapps.auth.webflux.services.V2SessionManagerAsync;
import com.trecapps.auth.webflux.services.TrecCookieSaverAsync;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Optional;

@RestController
@RequestMapping("/refresh_token")
@ConditionalOnProperty(prefix = "trecauth", name="use-cookie", havingValue = "true")
public class CookieController extends TrecCookieSaverAsync {

    CookieBase cookieBase;

    @Autowired
    protected CookieController(
            V2SessionManagerAsync sessionManager1,
            JwtTokenServiceAsync tokenService1,
            IUserStorageServiceAsync userStorageService1,
            CookieBase cookieBase,
            @Value("${trecauth.app}") String app1) {
        super(sessionManager1, tokenService1, userStorageService1, app1);
        this.cookieBase = cookieBase;
    }

    boolean isMfaRequired(TcUser user, String app) {
        for(MfaReq req: user.getMfaRequirements())
        {
            if(app.equals(req.getApp()))
                return req.isRequireMfa();
        }
        return false;
    }

    @GetMapping
    public Mono<ResponseEntity<LoginToken>> checkRefresh(@RequestHeader("User-Agent") String userClient,
                                                         @RequestParam("app") String app,
                                                         Authentication authentication){

        if(authentication instanceof TrecAuthentication tAuth){

            tAuth.setUseCookie(true);

            return this.prepLoginTokens(tAuth, userClient)
                    .flatMap((Optional<LoginToken> oToken) ->{
                                return oToken.<Mono<? extends ResponseEntity<LoginToken>>>map(
                                        loginToken -> this.cookieBase.assertAppAdded(tAuth.getAccount().getId(), tAuth.getSessionId(), null)

                                        .thenReturn(loginToken)
                                                .doOnNext((LoginToken token) -> {
                                                    if(isMfaRequired(tAuth.getUser(), app))
                                                        token.setToken_type("User-requires_mfa");
                                                })
                                                .map(ResponseEntity::ok)
                                        )

                                        .orElseGet(() -> Mono.just(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR)));
                            }

                    );
        }
        return Mono.just(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }





}
