package com.trecapps.auth.webflux.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.models.AnonymousAuthentication;
import com.trecapps.auth.common.models.TrecAuthentication;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

public class TrecAuthManagerReactiveTest {

    TrecAuthManagerReactive manager = new TrecAuthManagerReactive();

    @Test
    void testValidAuth() {
        TrecAuthentication trecAuthentication =
                new TrecAuthentication(ObjectTestProvider.getTcUser());

        Mono<Authentication> monoAuth = manager.authenticate(trecAuthentication);

        StepVerifier.create(monoAuth).consumeNextWith((Authentication authentication) -> {
            Assertions.assertTrue(authentication instanceof TrecAuthentication);
            Assertions.assertTrue(authentication.isAuthenticated());
        }).verifyComplete();
    }

    @Test
    void testInvalidAuth(){
        Authentication authentication = new AnonymousAuthentication();
        authentication.setAuthenticated(true);
        Mono<Authentication> monoAuth = manager.authenticate(authentication);

        StepVerifier.create(monoAuth).consumeNextWith((Authentication auth) -> {
            Assertions.assertFalse(auth.isAuthenticated());
        }).verifyComplete();
    }
}
