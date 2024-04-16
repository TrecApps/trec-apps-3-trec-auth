package com.trecapps.auth.services.webflux;

import com.trecapps.auth.models.TrecAuthentication;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import reactor.core.publisher.Mono;

public class TrecAuthManager implements ReactiveAuthenticationManager {
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {

        if(authentication instanceof TrecAuthentication trecAuthentication)
            trecAuthentication.setAuthenticated(true);
        else if(authentication != null)
            authentication.setAuthenticated(false);

        assert authentication != null;
        return Mono.just(authentication);
    }
}
