package com.trecapps.auth.web.services;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.models.primary.TrecAccount;
import com.trecapps.auth.webflux.services.IUserStorageServiceAsync;
import com.trecapps.auth.webflux.services.JwtTokenServiceAsync;
import com.trecapps.auth.webflux.services.V2SessionManagerAsync;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Field;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class JwtTokenServiceTest {

    @Mock
    IUserStorageService userStorageServiceAsync;
    @Mock
    V2SessionManager sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenService jwtTokenServiceAsync;

    @BeforeEach
    void setUp(){

        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey(0);
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey(0);




        jwtTokenServiceAsync = new JwtTokenService(
                userStorageServiceAsync,
                sessionManager,
                jwtKeyHolder,
                "app",
                1
        );
    }

    @Test
    void assertKeysActive() throws NoSuchFieldException, IllegalAccessException {

        Class<JwtTokenService> jwtClass = JwtTokenService.class;

        Field keyArrayField = jwtClass.getDeclaredField("keyArray");
        keyArrayField.setAccessible(true);

        JwtKeyArray keyArray = (JwtKeyArray) keyArrayField.get(jwtTokenServiceAsync);

        Class<JwtKeyArray> jwtKeyArrayClass = JwtKeyArray.class;
        Field keyHolderField = jwtKeyArrayClass.getDeclaredField("keys");
        keyHolderField.setAccessible(true);

        AtomicReference<LimitList<JwtKeyArray.JwtKeyPair>> keys = (AtomicReference<LimitList<JwtKeyArray.JwtKeyPair>>) keyHolderField.get(keyArray);

        JwtKeyArray.JwtKeyPair pair = keys.get().peek();

        Object oPublicKey = pair.publicKey();

        Object oPrivateKey = pair.privateKey();

        Assertions.assertNotNull(oPublicKey);

        Assertions.assertNotNull(oPrivateKey);
    }

    void assertDecode(String token, String claim, Object expectedValue){
        JwtKeyArray.DecodedHolder decodedJwt = jwtTokenServiceAsync.decodeToken(token);
        Assertions.assertTrue(decodedJwt.getDecodedJwt().isPresent());
        Claim claimValue = decodedJwt.getDecodedJwt().get().getClaim(claim);

        if(expectedValue == null){
            Assertions.assertTrue(claimValue.isNull());
            return;
        }

        if(expectedValue instanceof Boolean expectBool){
            Assertions.assertEquals(expectBool, claimValue.asBoolean());
            return;
        }

        if(expectedValue instanceof String expectStr){
            Assertions.assertEquals(expectStr, claimValue.asString());
            return;
        }

    }

    @Test
    void testGenerateToken(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime time = new TokenTime();
        time.setSession("aaaaaa");

        Mockito.doReturn(time).when(sessionManager).addSession(
                anyString(),
                anyString(),
                anyString(),
                Mockito.any(Boolean.class)
        );

        TokenTime tokenTime = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                false,
                "app");
        Assertions.assertNotNull(tokenTime);
        Assertions.assertNotNull(tokenTime.getToken());

        assertDecode(tokenTime.getToken(), "SessionId", "aaaaaa");
        assertDecode(tokenTime.getToken(), "mfa", false);
    }

    @Test
    void testGenerateTokenSession(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime time = new TokenTime();
        time.setSession("aaaaaa");


        TokenTime tokenTime = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                "app");


        Assertions.assertNotNull(tokenTime.getToken());
    }

    @Test
    void testGenerateTokenSessionExpires(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime time = new TokenTime();
        time.setSession("aaaaaa");


        TokenTime tokenTime = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                true,
                "app");


        Assertions.assertNotNull(tokenTime.getToken());
    }

    @Test
    void testGenerateTokenSessionMfa(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime time = new TokenTime();
        time.setSession("aaaaaa");


        TokenTime tokenTime = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                true,
                "app");
                    Assertions.assertNotNull(tokenTime);

                    Assertions.assertNotNull(tokenTime.getToken());
                    assertDecode(tokenTime.getToken(), "mfa", true);
    }

    @Test
    void testGenerateTokenSessionAddMfa(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime tokenTime = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                "app");

        Assertions.assertNotNull(tokenTime);
        assertDecode(tokenTime.getToken(), "mfa", false);

        tokenTime.setToken(jwtTokenServiceAsync.addMfa(tokenTime.getToken()).getToken());


        Assertions.assertNotNull(tokenTime);

        Assertions.assertNotNull(tokenTime.getToken());
        assertDecode(tokenTime.getToken(), "mfa", true);
    }

    @Test
    void testGetSessionId(){
        String session = jwtTokenServiceAsync.getSessionId(RSATestHelper.NO_SESSION_OR_BRAND_OR_EXP);
        Assertions.assertEquals("aaaaaa", session);
    }

    @Test
    void testRefresh(){
        TcUser user = ObjectTestProvider.getTcUser();

//        Mockito.doReturn().when(sessionManager).updateSessionExpiration(
//                anyString(),
//                anyString(),
//                any(OffsetDateTime.class)
//        );
        String refreshToken = jwtTokenServiceAsync.generateRefreshToken(user.getTrecAccount(), "bbbbbb");
        TokenTime tokenTime = jwtTokenServiceAsync.generateNewTokenFromRefresh(refreshToken);

        Assertions.assertNotNull(tokenTime.getToken());
        assertDecode(tokenTime.getToken(), "SessionId", "bbbbbb");
        assertDecode(tokenTime.getToken(), "ID", user.getId());
    }

    @Test
    void testVerifyToken(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        Mockito.doReturn(Optional.of(user)).when(userStorageServiceAsync).getAccountById(anyString());

        TokenTime tokenTime = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                "app");
        Assertions.assertNotNull(tokenTime);
        JwtKeyArray.DecodedHolder decodedJwt = jwtTokenServiceAsync.decodeToken(tokenTime.getToken());
        Assertions.assertTrue(decodedJwt.getDecodedJwt().isPresent());
        TokenFlags flags = new TokenFlags();
        TrecAuthentication trecAuth = jwtTokenServiceAsync.verifyToken(decodedJwt.getDecodedJwt().get(), flags);


        Assertions.assertNotNull(trecAuth);
        Assertions.assertEquals("aaaaaa", trecAuth.getSessionId());
        Assertions.assertEquals(user.getId(), trecAuth.getUser().getId());
    }
}
