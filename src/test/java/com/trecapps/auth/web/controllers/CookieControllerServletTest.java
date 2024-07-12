package com.trecapps.auth.web.controllers;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.web.services.IUserStorageService;
import com.trecapps.auth.web.services.JwtTokenService;
import com.trecapps.auth.web.services.V2SessionManager;
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
import software.amazon.awssdk.http.HttpStatusCode;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class CookieControllerServletTest {

    V2SessionManager sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenService tokenService;

    @Mock
    IUserStorageService userStorageService;

    com.trecapps.auth.web.controllers.CookieBase cookieBase;

    Map<String, String> fieldValues = new HashMap<>();

    CookieController cookieController;

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        sessionManager = new V2SessionManager(userStorageService, true);


        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey();
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey();
        tokenService = new JwtTokenService(
                userStorageService,
                sessionManager,
                jwtKeyHolder,
                "app"
        );



        fieldValues.put("cookieName", "Trec-Apps");
        fieldValues.put("domain", "trecapps.com");
        fieldValues.put("appName", "app");

        cookieBase = new com.trecapps.auth.web.controllers.CookieBase();

        Class<com.trecapps.auth.web.controllers.CookieBase> cookieClass = CookieBase.class;

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

        try(MockedStatic<SecurityContextHolder> staticMock = Mockito.mockStatic(SecurityContextHolder.class))
        {
            staticMock.when(SecurityContextHolder::getContext).thenReturn(context);

            Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

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

            ResponseEntity<LoginToken> response = cookieController.checkRefresh("");

            Assertions.assertEquals(HttpStatusCode.OK, response.getStatusCode().value());
            Assertions.assertEquals(token, response.getBody());
        }
    }

    @Test
    void testFailedRefresh()
    {
        ResponseEntity<LoginToken> response = cookieController.checkRefresh("");

        Assertions.assertEquals(HttpStatusCode.NOT_FOUND, response.getStatusCode().value());

    }

}
