package com.trecapps.auth.web.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.util.Optional;
@ExtendWith(MockitoExtension.class)
public class TrecCookieSaverTest {
    JwtTokenService tokenService;
    TrecCookieSaver cookieSaver;

    @Mock
    V2SessionManager sessionManager;
    @Mock
    IUserStorageService userStorageService;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    TcUser user = ObjectTestProvider.getTcUser();

    @BeforeEach
    void setUp(){
        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey();
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey();
        tokenService = new JwtTokenService(
                userStorageService,
                sessionManager,
                jwtKeyHolder,
                "app"
        );

        cookieSaver = new TrecCookieSaver(
                sessionManager,
                tokenService,
                userStorageService,
                "app");


    }

    private static final String CLIENT_STRING = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0";

    @Test
    void testGetLoginTokensSuccess(){
        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(sessionListV2.getSessions()).when(sessionManager).getSessionList(user.getId());
        TrecAuthentication auth = new TrecAuthentication(user);
        auth.setSessionId("cccccc");
        LoginToken token = cookieSaver.getLoginTokens(auth, CLIENT_STRING);

        Assertions.assertNotNull(token);
        Assertions.assertNotNull(token.getAccess_token());
        Assertions.assertNotNull(token.getRefresh_token());
    }

    @Test
    void testGetLoginTokensSuccessBrand(){
        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app","id");
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        TcBrands brand = ObjectTestProvider.getBrand();

        Mockito.doReturn(Optional.of(brand))
                .when(userStorageService).getBrandById("id");

        Mockito.doReturn(sessionListV2.getSessions()).when(sessionManager).getSessionList(user.getId());
        TrecAuthentication auth = new TrecAuthentication(user);
        auth.setSessionId("cccccc");
        LoginToken token = cookieSaver.getLoginTokens(auth, CLIENT_STRING);

        Assertions.assertNotNull(token);
        Assertions.assertNotNull(token.getAccess_token());
        Assertions.assertNotNull(token.getRefresh_token());
    }


    @Test
    void testGetBrand() {
        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app","id");
        sessionV2.setDeviceId("cccccc");

        TcBrands brand = ObjectTestProvider.getBrand();

        Mockito.doReturn(Optional.of(brand))
                .when(userStorageService).getBrandById("id");

        TcBrands returnedBrand = cookieSaver.getBrand(sessionV2, "id");

        Assertions.assertNotNull(returnedBrand);

        Assertions.assertEquals(brand, returnedBrand);
    }
}
