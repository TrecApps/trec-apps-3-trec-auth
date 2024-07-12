package com.trecapps.auth.common.models;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AnonymousAuthenticationTest {

    @Test
    void testAnonymousAuthentication(){
        AnonymousAuthentication auth = new AnonymousAuthentication();

        Collection<GrantedAuthority> grantedAuthorities = (Collection<GrantedAuthority>) auth.getAuthorities();

        Assertions.assertEquals(0, grantedAuthorities.size());

        Assertions.assertNull(auth.getCredentials());
        Assertions.assertNull(auth.getDetails());
        Assertions.assertNull(auth.getPrincipal());
        Assertions.assertTrue(auth.getName().isEmpty());
        Assertions.assertFalse(auth.isAuthenticated());

        auth.setAuthenticated(true);

        Assertions.assertFalse(auth.isAuthenticated());


    }
}
