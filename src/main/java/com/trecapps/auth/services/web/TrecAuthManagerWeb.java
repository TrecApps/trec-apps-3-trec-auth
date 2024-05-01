package com.trecapps.auth.services.web;

import com.trecapps.auth.models.TrecAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class TrecAuthManagerWeb implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(authentication instanceof TrecAuthentication trecAuthentication)
        {
            trecAuthentication.setAuthenticated(true);
        }
        return authentication;
    }
}
