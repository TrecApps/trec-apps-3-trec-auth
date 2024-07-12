package com.trecapps.auth.common.models;

import com.trecapps.auth.ObjectTestProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class TrecAuthenticationTest {

    TcUser user = ObjectTestProvider.getTcUser();
    TrecAuthentication auth;

    @BeforeEach
    void setUp(){


        user.getAuthRoles().add("EMAIL_VERIFIED");
        user.getAuthRoles().add("PHONE_VERIFIED");

        user.addAuthority("MFA");

        auth = new TrecAuthentication(user);
    }

    @Test
    void testAuthentication(){
        Assertions.assertTrue(auth.getCredentials().toString().isEmpty()); // TrecAuthentication does not hold the password
        Assertions.assertEquals(auth.getDetails(), user);
        Assertions.assertEquals(auth.getUser(), user);
        Assertions.assertTrue(auth.isRegularSession());
        auth.setRegularSession(false);
        Assertions.assertFalse(auth.isRegularSession());
        Assertions.assertEquals("John Doe", auth.getPrincipal());
        Assertions.assertEquals("John Doe", auth.getName());

        Collection<GrantedAuthority> grantedAuthorities = (Collection<GrantedAuthority>) auth.getAuthorities();

        Assertions.assertEquals(3, grantedAuthorities.size());
    }
}
