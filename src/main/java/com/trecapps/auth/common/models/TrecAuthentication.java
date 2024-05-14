package com.trecapps.auth.common.models;

import com.trecapps.auth.common.models.primary.TrecAccount;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;


public class TrecAuthentication implements Authentication {

    @Getter
    TcUser user;
    boolean isTrusted;

    boolean regularSession;

    LoginToken loginToken;

    String sessionId;

    @Getter
    @Setter
    boolean useCookie;

//    @Setter
//    @Getter
//    Map<String, String> claims = new HashMap<>();


    public UUID getBrandId() {
        return brandId;
    }

    public void setBrandId(UUID brandId) {
        this.brandId = brandId;
    }

    UUID brandId;



    public String getSessionId()
    {
        return sessionId;
    }

    public void setSessionId(String sessionId1)
    {
        sessionId = sessionId1;
    }

    public TrecAuthentication(TcUser user)
    {
        this.user = user;
        isTrusted = true;
        regularSession = true;
    }

    public void setLoginToken(LoginToken token) {loginToken = token;}

    public LoginToken getLoginToken(){return loginToken;}

    public boolean isRegularSession() {
        return regularSession;
    }

    public void setRegularSession(boolean regularSession) {
        this.regularSession = regularSession;
    }

    public TrecAccount getAccount()
    {
        return user.getTrecAccount();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return user.getPassword();
    }

    @Override
    public Object getDetails() {
        return user;
    }

    @Override
    public Object getPrincipal() {
        return user.getUsername();
    }

    @Override
    public boolean isAuthenticated() {
        return user.isAccountNonExpired() && user.isAccountNonLocked() && isTrusted;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        isTrusted = isAuthenticated;
    }

    @Override
    public String getName() {
        return user.getUsername();
    }


}
