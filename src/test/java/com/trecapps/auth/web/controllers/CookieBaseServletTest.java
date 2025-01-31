package com.trecapps.auth.web.controllers;

import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.JwtKeyArray;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.SessionV2;
import com.trecapps.auth.web.services.IUserStorageService;
import com.trecapps.auth.web.services.JwtTokenService;
import com.trecapps.auth.web.services.V2SessionManager;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class CookieBaseServletTest {

    V2SessionManager sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenService tokenService;

    @Mock
    IUserStorageService userStorageService;

    com.trecapps.auth.web.controllers.CookieBase cookieBase;

    Map<String, String> fieldValues = new HashMap<>();

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        sessionManager = new V2SessionManager(userStorageService, true);


        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey(0);
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey(0);
        tokenService = new JwtTokenService(
                userStorageService,
                sessionManager,
                jwtKeyHolder,
                new JwtKeyArray(1),
                "app",
                1
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
    }

    @Test
    void testGetMethods(){
        Assertions.assertEquals("Trec-Apps", this.cookieBase.getCookieName());
        Assertions.assertEquals("trecapps.com", this.cookieBase.getDomain());
        Assertions.assertEquals("app", this.cookieBase.getCookieAppName());
    }

    @Test
    void testSetCookie(){
        List<Cookie> cookies = new ArrayList<>(1);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            Cookie arg = invoke.getArgument(0, Cookie.class);
            cookies.add(arg);
            return null;
        }).when(response).addCookie(any(Cookie.class));

        cookieBase.SetCookie(response, RSATestHelper.BASIC_REFRESH_TOKEN);

        Assertions.assertEquals(1, cookies.size());

        Cookie cookie = cookies.get(0);

        Assertions.assertTrue(cookie.isHttpOnly());
        Assertions.assertTrue(cookie.getSecure());
        Assertions.assertEquals("/", cookie.getPath());
        Assertions.assertEquals(RSATestHelper.BASIC_REFRESH_TOKEN, cookie.getValue());
    }

    @Test
    void testRemoveCookie() {
        List<Cookie> cookies = new ArrayList<>(1);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);


        Cookie requestCookie = new Cookie("Trec-Apps", RSATestHelper.BASIC_REFRESH_TOKEN);

        Mockito.doReturn(new Cookie[] {requestCookie}).when(request).getCookies();
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            Cookie arg = invoke.getArgument(0, Cookie.class);
            cookies.add(arg);
            return null;
        }).when(response).addCookie(any(Cookie.class));

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setDeviceId("bbbbbb");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            SessionListV2 sessions = invoke.getArgument(0, SessionListV2.class);
            Assertions.assertTrue(sessions.getSessions().isEmpty());
            return null;
        }).when(userStorageService).saveSessions(any(SessionListV2.class), anyString());

        cookieBase.RemoveCookie(request, response, "id");

        Assertions.assertEquals(1, cookies.size());

        Cookie cookie = cookies.get(0);

        Assertions.assertEquals("/", cookie.getPath());
        Assertions.assertEquals(0, cookie.getMaxAge());
    }

    @Test
    void testRemoveCookieNone() {
        List<Cookie> cookies = new ArrayList<>(1);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        Mockito.doReturn(new Cookie[0]).when(request).getCookies();
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            Cookie arg = invoke.getArgument(0, Cookie.class);
            cookies.add(arg);
            return null;
        }).when(response).addCookie(any(Cookie.class));


        cookieBase.RemoveCookie(request, response, "id");

        Assertions.assertEquals(1, cookies.size());

        Cookie cookie = cookies.get(0);

        Assertions.assertEquals("/", cookie.getPath());
        Assertions.assertEquals(0, cookie.getMaxAge());
    }
}
