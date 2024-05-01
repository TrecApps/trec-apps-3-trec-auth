package com.trecapps.auth.services.webflux;

import com.trecapps.auth.models.TrecAuthentication;
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
                        trecAuthentication.setAuthenticated(true);
                });
    }
}
