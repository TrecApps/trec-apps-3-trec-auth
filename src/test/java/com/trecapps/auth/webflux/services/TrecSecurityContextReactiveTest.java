package com.trecapps.auth.webflux.services;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.ISecurityAlertHandler;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.AnonymousAuthentication;
import com.trecapps.auth.common.models.LoginToken;
import com.trecapps.auth.common.models.TcUser;
import com.trecapps.auth.common.models.TrecAuthentication;
import lombok.Getter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class TrecSecurityContextReactiveTest {

    @Mock
    V2SessionManagerAsync sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenServiceAsync tokenService;

    @Mock
    IUserStorageServiceAsync userStorageService;

    class MockSecurityHandler implements ISecurityAlertHandler {

        @Override
        public void alertNullAccount(String ipAddress, String path, String query, String method) {
            called = true;
        }

        public boolean called = false;
    }

    MockSecurityHandler securityHandler = new MockSecurityHandler();

    TrecSecurityContextReactive trecSecurtyContext;

    @BeforeEach
    void setUp(){
        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey();
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey();
        tokenService = new JwtTokenServiceAsync(
                userStorageService,
                sessionManager,
                jwtKeyHolder,
                "app"
        );



        trecSecurtyContext = new TrecSecurityContextReactive(
                tokenService,
                sessionManager,
                userStorageService,
                securityHandler,
                "app",
                "trecapps.com",
                "trec-app",
                "trec-app",
                false
        );
    }

    @Test
    void testSaveWithCookie(){
        List<ResponseCookie> cookies = new ArrayList<>();
        ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);
        SecurityContext context = Mockito.mock(SecurityContext.class);
        ServerHttpResponse response = Mockito.mock(ServerHttpResponse.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);
        HttpHeaders headers = Mockito.mock(HttpHeaders.class);


        LoginToken loginToken= new LoginToken();
        loginToken.setRefresh_token(RSATestHelper.BASIC_REFRESH_TOKEN);

        TcUser user = ObjectTestProvider.getTcUser();
        TrecAuthentication trecAuthentication = new TrecAuthentication(user);
        trecAuthentication.setLoginToken(loginToken);


        Mockito.doReturn(trecAuthentication).when(context).getAuthentication();
        Mockito.doReturn(request).when(exchange).getRequest();
        Mockito.doReturn(headers).when(request).getHeaders();
        Mockito.doReturn(response).when(exchange).getResponse();

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            ResponseCookie cookie = invoke.getArgument(0, ResponseCookie.class);
            cookies.add(cookie);
            return null;
        }).when(response).addCookie(Mockito.any(ResponseCookie.class));

        Mono<Void> mono = trecSecurtyContext.save(exchange, context);

        StepVerifier.create(mono)
                .verifyComplete();
        Assertions.assertEquals(1, cookies.size());
        ResponseCookie cookie = cookies.get(0);
        Assertions.assertTrue(cookie.isSecure());
        Assertions.assertTrue(cookie.isHttpOnly());
        Assertions.assertEquals(RSATestHelper.BASIC_REFRESH_TOKEN, cookie.getValue());
        Assertions.assertEquals("/", cookie.getPath());
    }

    @Test
    void testSaveNoCookie(){
        List<ResponseCookie> cookies = new ArrayList<>();
        ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);
        SecurityContext context = Mockito.mock(SecurityContext.class);
        ServerHttpResponse response = Mockito.mock(ServerHttpResponse.class);

        Mockito.lenient().doAnswer((InvocationOnMock invoke) -> {
            ResponseCookie cookie = invoke.getArgument(0, ResponseCookie.class);
            cookies.add(cookie);
            return null;
        }).when(response).addCookie(Mockito.any(ResponseCookie.class));
        Mono<Void> mono = trecSecurtyContext.save(exchange, context);

        StepVerifier.create(mono)
                .verifyComplete();
        Assertions.assertTrue(cookies.isEmpty());
    }

    void prepPath(ServerHttpRequest req, String path){
        RequestPath pathObj = Mockito.mock(RequestPath.class);
        Mockito.doReturn(path).when(pathObj).value();
        Mockito.doReturn(pathObj).when(req).getPath();
    }

    @Test
    void testLoadFromCookie()
    {
        TcUser user = ObjectTestProvider.getTcUser();
        ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);

        Mockito.doReturn(request).when(exchange).getRequest();

        prepPath(request, "/refresh_token");

        MultiValueMap<String, HttpCookie> cookieMap = new LinkedMultiValueMap<>();
        HttpCookie cookie = new HttpCookie("trec-app", RSATestHelper.BASIC_REFRESH_TOKEN);

        cookieMap.add("trec-app", cookie);
        Mockito.doReturn(cookieMap).when(request).getCookies();

        Mockito.doReturn(Mono.just(Optional.of(user))).when(userStorageService).getAccountById(anyString());

        Mono<SecurityContext> mono = this.trecSecurtyContext.load(exchange);

        StepVerifier.create(mono)
                .consumeNextWith((SecurityContext context) -> {
                    Authentication authentication = context.getAuthentication();
                    Assertions.assertTrue(authentication instanceof TrecAuthentication);
                    TrecAuthentication trecAuthentication = (TrecAuthentication) authentication;
                    Assertions.assertEquals(user, trecAuthentication.getUser());
                }).verifyComplete();
    }


    @Test
    void testLoadFromHeader()
    {
        TcUser user = ObjectTestProvider.getTcUser();
        ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", RSATestHelper.NO_SESSION_OR_BRAND_OR_EXP);

        Mockito.doReturn(request).when(exchange).getRequest();

        prepPath(request, "/endpoint");

        Mockito.doReturn(headers).when(request).getHeaders();
        Mockito.doReturn(Mono.just(true)).when(sessionManager).isValidSession(anyString(), anyString(), anyString());

        Mockito.doReturn(Mono.just(Optional.of(user))).when(userStorageService).getAccountById(anyString());

        Mono<SecurityContext> mono = this.trecSecurtyContext.load(exchange);

        StepVerifier.create(mono)
                .consumeNextWith((SecurityContext context) -> {
                    Authentication authentication = context.getAuthentication();
                    Assertions.assertTrue(authentication instanceof TrecAuthentication);
                    TrecAuthentication trecAuthentication = (TrecAuthentication) authentication;
                    Assertions.assertEquals(user, trecAuthentication.getUser());
                }).verifyComplete();
    }

    @Test
    void testAlert() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Assertions.assertFalse(this.securityHandler.called);

        Mockito.doReturn(Mono.just(Optional.empty()))
                .when(userStorageService).getAccountById(anyString());

        Class<TrecSecurityContextReactive> tClass = TrecSecurityContextReactive.class;
        Method targetMethod = tClass.getDeclaredMethod(
                "handleSecurityDecoding",
                DecodedJWT.class,
                SecurityContext.class, ServerHttpRequest.class);
        targetMethod.setAccessible(true);

        DecodedJWT decoded = this.tokenService.decodeToken(RSATestHelper.NO_SESSION_OR_BRAND_OR_EXP);

        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);
        InetSocketAddress address = Mockito.mock(InetSocketAddress.class);
        Mockito.doReturn(new LinkedMultiValueMap<>()).when(request).getQueryParams();
        Mockito.doReturn(address).when(request).getRemoteAddress();
        Mockito.doReturn("localhost:2000").when(address).toString();
        Mockito.doReturn(HttpMethod.GET).when(request).getMethod();

        RequestPath path = Mockito.mock(RequestPath.class);
        Mockito.doReturn("/some_endpoint").when(path).toString();
        Mockito.doReturn(path).when(request).getPath();


        Mono<SecurityContext> mono = (Mono<SecurityContext>)targetMethod.invoke(
                this.trecSecurtyContext,
                decoded,
                SecurityContextHolder.createEmptyContext(),
                request
                );

        StepVerifier.create(mono)
                .consumeNextWith((SecurityContext context) -> {
                    Assertions.assertTrue(this.securityHandler.called);
                }).verifyComplete();
    }

    @Test
    void testLoadBlankFromCookie()
    {
        TcUser user = ObjectTestProvider.getTcUser();
        ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);

        Mockito.doReturn(request).when(exchange).getRequest();

        prepPath(request, "/refresh_token");

        MultiValueMap<String, HttpCookie> cookieMap = new LinkedMultiValueMap<>();
        HttpCookie cookie = new HttpCookie("trec-app", "A-Very_Bad_token");

        cookieMap.add("trec-app", cookie);
        Mockito.doReturn(cookieMap).when(request).getCookies();

        Mockito.doReturn(new InetSocketAddress("1.2.3.4", 80)).when(request).getRemoteAddress();

        //Mockito.doReturn(Mono.just(Optional.of(user))).when(userStorageService).getAccountById(anyString());

        Mono<SecurityContext> mono = this.trecSecurtyContext.load(exchange);

        StepVerifier.create(mono)
                .consumeNextWith((SecurityContext context) -> {
                    Authentication authentication = context.getAuthentication();
                    Assertions.assertTrue(authentication instanceof AnonymousAuthentication);
                }).verifyComplete();
    }

    @Test
    void testLoadBlankFromHeader()
    {
        TcUser user = ObjectTestProvider.getTcUser();
        ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);
        ServerHttpRequest request = Mockito.mock(ServerHttpRequest.class);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "SomeBadHeaderToken");

        Mockito.doReturn(request).when(exchange).getRequest();

        prepPath(request, "/endpoint");

        Mockito.doReturn(headers).when(request).getHeaders();
        Mockito.doReturn(new InetSocketAddress("1.2.3.4", 80)).when(request).getRemoteAddress();
        Mono<SecurityContext> mono = this.trecSecurtyContext.load(exchange);

        StepVerifier.create(mono)
                .consumeNextWith((SecurityContext context) -> {
                    Authentication authentication = context.getAuthentication();
                    Assertions.assertTrue(authentication instanceof AnonymousAuthentication);
                }).verifyComplete();
    }
}
