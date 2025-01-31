package com.trecapps.auth.webflux.controllers;

import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.JwtKeyArray;
import com.trecapps.auth.common.models.SessionListV2;
import com.trecapps.auth.common.models.SessionV2;
import com.trecapps.auth.webflux.services.IUserStorageServiceAsync;
import com.trecapps.auth.webflux.services.JwtTokenServiceAsync;
import com.trecapps.auth.webflux.services.V2SessionManagerAsync;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import reactor.core.publisher.Mono;

import java.lang.reflect.Field;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class CookieBaseReactiveTest {

    V2SessionManagerAsync sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenServiceAsync tokenService;

    @Mock
    IUserStorageServiceAsync userStorageService;

    CookieBase cookieBase;

    Map<String, String> fieldValues = new HashMap<>();

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        sessionManager = new V2SessionManagerAsync(userStorageService, true);


        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey(0);
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey(0);
        tokenService = new JwtTokenServiceAsync(
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

    }

    @Test
    void testGetMethods(){
        Assertions.assertEquals("Trec-Apps", this.cookieBase.getCookieName());
        Assertions.assertEquals("trecapps.com", this.cookieBase.getDomain());
        Assertions.assertEquals("app", this.cookieBase.getCookieAppName());
    }

    @Test
    void testSetCookie(){
        List<ResponseCookie> cookies = new ArrayList<>(1);
        ServerHttpResponse response = Mockito.mock(ServerHttpResponse.class);

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ResponseCookie arg = invoke.getArgument(0, ResponseCookie.class);
            cookies.add(arg);
            return null;
        }).when(response).addCookie(any(ResponseCookie.class));

        cookieBase.SetCookie(response, RSATestHelper.BASIC_REFRESH_TOKEN);

        Assertions.assertEquals(1, cookies.size());

        ResponseCookie cookie = cookies.get(0);

        Assertions.assertTrue(cookie.isHttpOnly());
        Assertions.assertTrue(cookie.isSecure());
        Assertions.assertEquals("/", cookie.getPath());
        Assertions.assertEquals(RSATestHelper.BASIC_REFRESH_TOKEN, cookie.getValue());
    }

    @Test
    void testRemoveCookie() {
        List<ResponseCookie> cookies = new ArrayList<>(1);
        ServerHttpResponse response = Mockito.mock(ServerHttpResponse.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);


        HttpCookie requestCookie = new HttpCookie("Trec-apps", RSATestHelper.BASIC_REFRESH_TOKEN);


        MultiValueMap<String, HttpCookie> requestCookies = Mockito.mock(MultiValueMap.class);
        Mockito.doReturn(requestCookie).when(requestCookies).getFirst(anyString());


        Mockito.doReturn(requestCookies).when(request).getCookies();
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ResponseCookie arg = invoke.getArgument(0, ResponseCookie.class);
            cookies.add(arg);
            return null;
        }).when(response).addCookie(any(ResponseCookie.class));

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setDeviceId("bbbbbb");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            SessionListV2 sessions = invoke.getArgument(0, SessionListV2.class);
            Assertions.assertTrue(sessions.getSessions().isEmpty());
            return Mono.empty();
        }).when(userStorageService).saveSessionsMono(any(SessionListV2.class), anyString());

        cookieBase.RemoveCookie(response, request, "id");

        Assertions.assertEquals(1, cookies.size());

        ResponseCookie cookie = cookies.get(0);

        Assertions.assertEquals("/", cookie.getPath());
        Assertions.assertTrue(cookie.getMaxAge().isZero());
    }

    @Test
    void testRemoveCookieNone() {
        List<ResponseCookie> cookies = new ArrayList<>(1);
        ServerHttpResponse response = Mockito.mock(ServerHttpResponse.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);

        MultiValueMap<String, HttpCookie> requestCookies = new LinkedMultiValueMap<>();

        Mockito.doReturn(requestCookies).when(request).getCookies();
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ResponseCookie arg = invoke.getArgument(0, ResponseCookie.class);
            cookies.add(arg);
            return null;
        }).when(response).addCookie(any(ResponseCookie.class));


        cookieBase.RemoveCookie(response, request, "id");

        Assertions.assertEquals(1, cookies.size());

        ResponseCookie cookie = cookies.get(0);

        Assertions.assertEquals("/", cookie.getPath());
        Assertions.assertTrue(cookie.getMaxAge().isZero());
    }


}
