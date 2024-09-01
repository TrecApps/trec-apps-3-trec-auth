package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.TrecAuthentication;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class TrecAuthManagerReactive implements ReactiveAuthenticationManager {
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {

        if(authentication instanceof TrecAuthentication trecAuthentication){
            if(trecAuthentication.isMfaBlock())
                return Mono.error(new BadCredentialsException("MFA Required"));
            authentication.setAuthenticated(true);
            return Mono.just(authentication);
        }
        return Mono.empty();
     }
}
