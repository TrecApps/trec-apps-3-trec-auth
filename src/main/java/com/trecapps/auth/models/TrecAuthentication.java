package com.trecapps.auth.models;

import com.trecapps.auth.models.primary.TrecAccount;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;


public class TrecAuthentication implements Authentication {

    TrecAccount account;
    boolean isTrusted;

    boolean regularSession;

    public TrecAuthentication(TrecAccount account)
    {
        this.account = account;
        isTrusted = true;
        regularSession = true;
    }

    public boolean isRegularSession() {
        return regularSession;
    }

    public void setRegularSession(boolean regularSession) {
        this.regularSession = regularSession;
    }

    public TrecAccount getAccount()
    {
        return account;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return account.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return account.getPassword();
    }

    @Override
    public Object getDetails() {
        return account;
    }

    @Override
    public Object getPrincipal() {
        return account.getUsername();
    }

    @Override
    public boolean isAuthenticated() {
        return account.isAccountNonExpired() && account.isAccountNonLocked() && isTrusted;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        isTrusted = isAuthenticated;
    }

    @Override
    public String getName() {
        return account.getUsername();
    }


}
