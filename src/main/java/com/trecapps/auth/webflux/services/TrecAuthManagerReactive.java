package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.TrecAuthentication;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class TrecAuthManagerReactive implements ReactiveAuthenticationManager {
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {

        return Mono.just(authentication)
                .doOnNext((Authentication auth)-> {
                    if(auth instanceof TrecAuthentication trecAuthentication)
                        trecAuthentication.setAuthenticated(!trecAuthentication.isMfaBlock());
                    else auth.setAuthenticated(false);
                });
    }
}
