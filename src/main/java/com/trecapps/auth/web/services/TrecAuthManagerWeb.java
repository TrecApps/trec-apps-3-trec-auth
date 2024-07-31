package com.trecapps.auth.web.services;

import com.trecapps.auth.common.models.TrecAuthentication;
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
            trecAuthentication.setAuthenticated(!trecAuthentication.isMfaBlock());
        }
        else authentication.setAuthenticated(false);
        return authentication;
    }
}
