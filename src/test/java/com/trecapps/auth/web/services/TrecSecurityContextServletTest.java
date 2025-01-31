package com.trecapps.auth.web.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.ISecurityAlertHandler;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.webflux.services.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.Invocation;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class TrecSecurityContextServletTest {

    @Mock
    V2SessionManager sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenService tokenService;

    @Mock
    IUserStorageService userStorageService;

    class MockSecurityHandler implements ISecurityAlertHandler {

        @Override
        public void alertNullAccount(String ipAddress, String path, String query, String method) {
            called = true;
        }

        boolean called = false;
    }

    ISecurityAlertHandler securityHandler = new MockSecurityHandler();

    TrecSecurityContextServlet trecSecurtyContext;

    @BeforeEach
    void setUp(){
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



        trecSecurtyContext = new TrecSecurityContextServlet(
                tokenService,
                sessionManager,
                userStorageService,
                securityHandler,
                "app",
                "trecapps.com",
                "trec-app",
                "trec-app",
                false,
                null
        );
    }

    void prepPath(HttpServletRequest req, String path){
        Mockito.doReturn(path).when(req).getRequestURI();
    }

    @Test
    void testSaveContext() {
        List<Cookie> cookies = new ArrayList<>();
        SecurityContext context = Mockito.mock(SecurityContext.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        LoginToken loginToken= new LoginToken();
        loginToken.setRefresh_token(RSATestHelper.BASIC_REFRESH_TOKEN);

        TcUser user = ObjectTestProvider.getTcUser();
        TrecAuthentication trecAuthentication = new TrecAuthentication(user);
        trecAuthentication.setLoginToken(loginToken);
        trecAuthentication.setUseCookie(true);

        Mockito.doReturn(trecAuthentication).when(context).getAuthentication();

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            Cookie cookie = invoke.getArgument(0, Cookie.class);
            cookies.add(cookie);
            return null;
        }).when(response).addCookie(any(Cookie.class));

        this.trecSecurtyContext.saveContext(context, request, response);
        Assertions.assertEquals(1, cookies.size());
        Cookie cookie = cookies.get(0);
        Assertions.assertTrue(cookie.getSecure());
        Assertions.assertTrue(cookie.isHttpOnly());
        Assertions.assertEquals(RSATestHelper.BASIC_REFRESH_TOKEN, cookie.getValue());
        Assertions.assertEquals("/", cookie.getPath());
    }

    @Test
    void testSaveNoCookie(){
        List<Cookie> cookies = new ArrayList<>();
        SecurityContext context = Mockito.mock(SecurityContext.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        Mockito.lenient().doAnswer((InvocationOnMock invoke) -> {
            Cookie cookie = invoke.getArgument(0, Cookie.class);
            cookies.add(cookie);
            return null;
        }).when(response).addCookie(any(Cookie.class));
        this.trecSecurtyContext.saveContext(context, request, response);
        Assertions.assertTrue(cookies.isEmpty());

        TcUser user = ObjectTestProvider.getTcUser();
        TrecAuthentication trecAuthentication = new TrecAuthentication(user);

        Mockito.doReturn(trecAuthentication).when(context).getAuthentication();
        this.trecSecurtyContext.saveContext(context, request, response);
        Assertions.assertTrue(cookies.isEmpty());
    }


    @Test
    void testLoadFromCookie() {
        HttpRequestResponseHolder httpRequestResponseHolder = Mockito.mock(HttpRequestResponseHolder.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.doReturn(request).when(httpRequestResponseHolder).getRequest();

        prepPath(request, "/refresh_token");
        TcUser user = ObjectTestProvider.getTcUser();

        Cookie cookie = new Cookie("trecapps.com", RSATestHelper.BASIC_REFRESH_TOKEN);
        Mockito.doReturn(new Cookie[]{cookie}).when(request).getCookies();
        Mockito.doReturn(Optional.of(user)).when(userStorageService).getAccountById(anyString());

        SecurityContext context = trecSecurtyContext.loadContext(httpRequestResponseHolder);

        Authentication authentication = context.getAuthentication();
        Assertions.assertTrue(authentication instanceof TrecAuthentication);
        TrecAuthentication trecAuthentication = (TrecAuthentication) authentication;
        Assertions.assertEquals(user, trecAuthentication.getUser());

        boolean containedContext = trecSecurtyContext.containsContext(request);
        Assertions.assertTrue(containedContext);
    }

    @Test
    void testLoadFromHeader() {
        HttpRequestResponseHolder httpRequestResponseHolder = Mockito.mock(HttpRequestResponseHolder.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.doReturn(request).when(httpRequestResponseHolder).getRequest();

        prepPath(request, "/endpoint");
        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn(RSATestHelper.NO_SESSION_OR_BRAND_OR_EXP).when(request).getHeader("Authorization");
        Mockito.doReturn(Optional.of(user)).when(userStorageService).getAccountById(anyString());

        Mockito.doReturn(true).when(sessionManager).isValidSession(anyString(), anyString(), anyString());

        SecurityContext context = trecSecurtyContext.loadContext(httpRequestResponseHolder);

        Authentication authentication = context.getAuthentication();
        Assertions.assertTrue(authentication instanceof TrecAuthentication);
        TrecAuthentication trecAuthentication = (TrecAuthentication) authentication;
        Assertions.assertEquals(user, trecAuthentication.getUser());

        boolean containedContext = trecSecurtyContext.containsContext(request);
        Assertions.assertTrue(containedContext);
    }

    @Test
    void testLoadFromHeaderWithPermissions() {
        HttpRequestResponseHolder httpRequestResponseHolder = Mockito.mock(HttpRequestResponseHolder.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.doReturn(request).when(httpRequestResponseHolder).getRequest();

        prepPath(request, "/endpoint");
        TcUser user = ObjectTestProvider.getTcUser();
        user.addAuthority("TREC_VERIFIED");
        user.setEmailVerified(true);
        user.setPhoneVerified(true);

        Mockito.doReturn(RSATestHelper.NO_SESSION_OR_BRAND_OR_EXP).when(request).getHeader("Authorization");
        Mockito.doReturn(Optional.of(user)).when(userStorageService).getAccountById(anyString());

        Mockito.doReturn(true).when(sessionManager).isValidSession(anyString(), anyString(), anyString());

        SecurityContext context = trecSecurtyContext.loadContext(httpRequestResponseHolder);

        Authentication authentication = context.getAuthentication();
        Assertions.assertTrue(authentication instanceof TrecAuthentication);
        TrecAuthentication trecAuthentication = (TrecAuthentication) authentication;
        Assertions.assertEquals(user, trecAuthentication.getUser());

        boolean containedContext = trecSecurtyContext.containsContext(request);
        Assertions.assertTrue(containedContext);
    }

    @Test
    void testLoadBlankFromCookie() {
        HttpRequestResponseHolder httpRequestResponseHolder = Mockito.mock(HttpRequestResponseHolder.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.doReturn(request).when(httpRequestResponseHolder).getRequest();

        prepPath(request, "/refresh_token");
        TcUser user = ObjectTestProvider.getTcUser();

        Cookie cookie = new Cookie("trecapps.com", "SomeBadCookie");
        Mockito.doReturn(new Cookie[]{cookie}).when(request).getCookies();
        Mockito.doReturn("/endpoint").when(request).getContextPath();
        Mockito.doReturn("1.2.3.4").when(request).getRemoteAddr();

        SecurityContext context = trecSecurtyContext.loadContext(httpRequestResponseHolder);

        Authentication authentication = context.getAuthentication();
        Assertions.assertNull(authentication);

        boolean containedContext = trecSecurtyContext.containsContext(request);
        Assertions.assertTrue(containedContext);
    }

    @Test
    void testLoadBlankFromHeader() {
        HttpRequestResponseHolder httpRequestResponseHolder = Mockito.mock(HttpRequestResponseHolder.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.doReturn(request).when(httpRequestResponseHolder).getRequest();

        prepPath(request, "/endpoint");
        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn("SomeBadHeaderToken").when(request).getHeader("Authorization");
        Mockito.doReturn("/endpoint").when(request).getContextPath();
        Mockito.doReturn("1.2.3.4").when(request).getRemoteAddr();

        SecurityContext context = trecSecurtyContext.loadContext(httpRequestResponseHolder);

        Authentication authentication = context.getAuthentication();
        Assertions.assertNull(authentication);

        boolean containedContext = trecSecurtyContext.containsContext(request);
        Assertions.assertTrue(containedContext);
    }

}
