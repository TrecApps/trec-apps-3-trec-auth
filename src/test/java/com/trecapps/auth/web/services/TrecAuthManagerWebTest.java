package com.trecapps.auth.web.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.models.AnonymousAuthentication;
import com.trecapps.auth.common.models.TrecAuthentication;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

public class TrecAuthManagerWebTest {

    TrecAuthManagerWeb manager = new TrecAuthManagerWeb();

    @Test
    void testValidAuth(){
        TrecAuthentication trecAuthentication = new TrecAuthentication(ObjectTestProvider.getTcUser());
        Authentication authentication = trecAuthentication;

        authentication = manager.authenticate(authentication);

        Assertions.assertTrue(authentication instanceof TrecAuthentication);
        Assertions.assertTrue(authentication.isAuthenticated());
    }

    @Test
    void testInvalidAuth(){
        Authentication authentication = new AnonymousAuthentication();
        authentication.setAuthenticated(true);
        authentication = manager.authenticate(authentication);

        Assertions.assertFalse(authentication.isAuthenticated());
    }
}
