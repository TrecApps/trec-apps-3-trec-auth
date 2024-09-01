package com.trecapps.auth.web.services;

import com.trecapps.auth.common.models.TrecAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class TrecAuthManagerWeb implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(authentication instanceof TrecAuthentication trecAuthentication)
        {
            if(trecAuthentication.isMfaBlock())
                throw new BadCredentialsException("MFA is required!");
            trecAuthentication.setAuthenticated(true);
        }
        else authentication.setAuthenticated(false);
        return authentication;
    }
}
