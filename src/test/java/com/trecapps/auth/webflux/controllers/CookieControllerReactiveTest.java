package com.trecapps.auth.webflux.controllers;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.webflux.services.IUserStorageServiceAsync;
import com.trecapps.auth.webflux.services.JwtTokenServiceAsync;
import com.trecapps.auth.webflux.services.V2SessionManagerAsync;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import software.amazon.awssdk.http.HttpStatusCode;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;


@ExtendWith(MockitoExtension.class)
public class CookieControllerReactiveTest {

    V2SessionManagerAsync sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenServiceAsync tokenService;

    @Mock
    IUserStorageServiceAsync userStorageService;

    CookieBase cookieBase;

    Map<String, String> fieldValues = new HashMap<>();

    CookieController cookieController;

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        sessionManager = new V2SessionManagerAsync(userStorageService, true);


        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey();
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey();
        tokenService = new JwtTokenServiceAsync(
                userStorageService,
                sessionManager,
                jwtKeyHolder,
                "app"
        );



        fieldValues.put("cookieName", "Trec-Apps");
        fieldValues.put("domain", "trecapps.com");
        fieldValues.put("appName", "app");

        cookieBase = new CookieBase();

        Class<CookieBase> cookieClass = CookieBase.class;

        fieldValues.forEach((String fieldName, String value) -> {
            Field field = null;
            try {
                field = cookieClass.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                throw new RuntimeException(e);
            }
            field.setAccessible(true);
            try {
                field.set(cookieBase, value);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        });

        Field field = cookieClass.getDeclaredField("tokenService");
        field.setAccessible(true);
        field.set(cookieBase, tokenService);

        field = cookieClass.getDeclaredField("sessionManager");
        field.setAccessible(true);
        field.set(cookieBase, sessionManager);

        cookieController = new CookieController(
                sessionManager,
                tokenService,
                userStorageService,
                cookieBase,
                "app"
        );
    }

    @Test
    void testSuccessRefresh(){
        LoginToken token = new LoginToken();
        token.setRefresh_token(RSATestHelper.BASIC_REFRESH_TOKEN);

        TrecAuthentication trecAuthentication = new TrecAuthentication(ObjectTestProvider.getTcUser());
        trecAuthentication.setSessionId("bbbbbb");
        trecAuthentication.setLoginToken(token);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(trecAuthentication);

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app","brandId");
        sessionV2.setDeviceId("bbbbbb");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);


        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            SessionListV2 sessions = invoke.getArgument(0, SessionListV2.class);
            Assertions.assertFalse(sessions.getSessions().isEmpty());
            SessionV2 session = sessions.getSessions().get(0);
            List<SessionApp> apps = session.getApps();
            Assertions.assertFalse(apps.isEmpty());
            SessionApp app = apps.get(0);
            Assertions.assertEquals("brandId", app.getBrandId());

            return null;
        }).when(userStorageService).saveSessions(any(SessionListV2.class), anyString());
        Mono<ResponseEntity<LoginToken>> mono = cookieController.checkRefresh("", trecAuthentication);

        StepVerifier.create(mono)
                        .consumeNextWith((ResponseEntity<LoginToken> response) -> {
                            Assertions.assertEquals(HttpStatusCode.OK, response.getStatusCode().value());
                            Assertions.assertEquals(token, response.getBody());
                        }).verifyComplete();


    }

    @Test
    void testFailedRefresh()
    {
        Mono<ResponseEntity<LoginToken>> mono = cookieController.checkRefresh("", null);

        StepVerifier.create(mono)
                        .consumeNextWith((ResponseEntity<LoginToken> response) ->{
                    Assertions.assertEquals(HttpStatusCode.NOT_FOUND, response.getStatusCode().value());
                }).verifyComplete();


    }

}