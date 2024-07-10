package com.trecapps.auth.webflux.services;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.models.primary.TrecAccount;
import lombok.SneakyThrows;
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
import java.lang.reflect.Method;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class JwtTokenServiceAsyncTest {

    @Mock
    IUserStorageServiceAsync userStorageServiceAsync;
    @Mock
    V2SessionManagerAsync sessionManager;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    JwtTokenServiceAsync jwtTokenServiceAsync;

    @BeforeEach
    void setUp(){

        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey();
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey();




        jwtTokenServiceAsync = new JwtTokenServiceAsync(
                userStorageServiceAsync,
                sessionManager,
                jwtKeyHolder,
                "app"
        );
    }

    @Test
    void assertKeysActive() throws NoSuchFieldException, IllegalAccessException {

        Class<JwtTokenServiceAsync> jwtClass = JwtTokenServiceAsync.class;
        Field publicKey = jwtClass.getDeclaredField("publicKey");
        Field privateKey = jwtClass.getDeclaredField("privateKey");

        publicKey.setAccessible(true);
        Object oPublicKey = publicKey.get(jwtTokenServiceAsync);

        privateKey.setAccessible(true);
        Object oPrivateKey = privateKey.get(jwtTokenServiceAsync);

        Assertions.assertNotNull(oPublicKey);
        Assertions.assertTrue(oPublicKey instanceof RSAPublicKey);

        Assertions.assertNotNull(oPrivateKey);
        Assertions.assertTrue(oPrivateKey instanceof RSAPrivateKey);
    }

    void assertDecode(String token, String claim, Object expectedValue){
        DecodedJWT decodedJwt = jwtTokenServiceAsync.decodeToken(token);

        Claim claimValue = decodedJwt.getClaim(claim);

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

        Mockito.doReturn(Mono.just(time)).when(sessionManager).addSession(
                anyString(),
                anyString(),
                anyString(),
                Mockito.any(Boolean.class)
        );

        Mono<Optional<TokenTime>> mono = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                false,
                "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TokenTime> oTokenTime) -> {
                    Assertions.assertTrue(oTokenTime.isPresent());
                    TokenTime tokenTime = oTokenTime.get();

                    Assertions.assertNotNull(tokenTime.getToken());

                    assertDecode(tokenTime.getToken(), "SessionId", "aaaaaa");
                    assertDecode(tokenTime.getToken(), "mfa", false);
                }).verifyComplete();
    }

    @Test
    void testGenerateTokenSession(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime time = new TokenTime();
        time.setSession("aaaaaa");


        Mono<Optional<TokenTime>> mono = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TokenTime> oTokenTime) -> {
                    Assertions.assertTrue(oTokenTime.isPresent());
                    TokenTime tokenTime = oTokenTime.get();

                    Assertions.assertNotNull(tokenTime.getToken());
                }).verifyComplete();
    }

    @Test
    void testGenerateTokenSessionMfa(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        TokenTime time = new TokenTime();
        time.setSession("aaaaaa");


        Mono<Optional<TokenTime>> mono = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                true,
                "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TokenTime> oTokenTime) -> {
                    Assertions.assertTrue(oTokenTime.isPresent());
                    TokenTime tokenTime = oTokenTime.get();

                    Assertions.assertNotNull(tokenTime.getToken());
                    assertDecode(tokenTime.getToken(), "mfa", true);
                }).verifyComplete();
    }

    @Test
    void testGenerateTokenSessionAddMfa(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        Mono<Optional<TokenTime>> mono = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                "app");

        mono = mono.map((Optional<TokenTime> oTokenTime) -> {
            Assertions.assertTrue(oTokenTime.isPresent());
            assertDecode(oTokenTime.get().getToken(), "mfa", false);

            return Optional.of(jwtTokenServiceAsync.addMfa(oTokenTime.get().getToken()));
        });

        StepVerifier.create(mono)
                .consumeNextWith((Optional<TokenTime> oTokenTime) -> {
                    Assertions.assertTrue(oTokenTime.isPresent());
                    TokenTime tokenTime = oTokenTime.get();

                    Assertions.assertNotNull(tokenTime.getToken());
                    assertDecode(tokenTime.getToken(), "mfa", true);
                }).verifyComplete();
    }

    @Test
    void testGetSessionId(){
        String session = jwtTokenServiceAsync.getSessionId(RSATestHelper.NO_SESSION_OR_BRAND_OR_EXP);
        Assertions.assertEquals("aaaaaa", session);
    }

    @Test
    void testRefresh(){
        TcUser user = ObjectTestProvider.getTcUser();

        Mockito.doReturn(Mono.just(new SessionListV2())).when(sessionManager).updateSessionExpiration(
                anyString(),
                anyString(),
                any(OffsetDateTime.class)
        );
        String refreshToken = jwtTokenServiceAsync.generateRefreshToken(user.getTrecAccount(), "bbbbbb");

        Mono<TokenTime> mono = jwtTokenServiceAsync.generateNewTokenFromRefresh(refreshToken);

        StepVerifier.create(mono)
                .consumeNextWith((TokenTime tokenTime) -> {
                    Assertions.assertNotNull(tokenTime.getToken());

                    assertDecode(tokenTime.getToken(), "SessionId", "bbbbbb");
                    assertDecode(tokenTime.getToken(), "ID", user.getId());
                        }).verifyComplete();
    }

    @Test
    void testVerifyToken(){
        TcUser user = ObjectTestProvider.getTcUser();
        TrecAccount account = user.getTrecAccount();

        Mockito.doReturn(Mono.just(Optional.of(user))).when(userStorageServiceAsync).getAccountById(anyString());

        Mono<Optional<TokenTime>> mono = jwtTokenServiceAsync.generateToken(
                account,
                "Windows 10 Firefox",
                null,
                "aaaaaa",
                false,
                "app");
        Mono<Optional<TrecAuthentication>> mono2 = mono.flatMap((Optional<TokenTime> time) -> {
            Assertions.assertTrue(time.isPresent());
            DecodedJWT decodedJwt = jwtTokenServiceAsync.decodeToken(time.get().getToken());
            TokenFlags flags = new TokenFlags();
            return jwtTokenServiceAsync.verifyToken(decodedJwt, flags);
        });

        StepVerifier.create(mono2)
                .consumeNextWith((Optional< TrecAuthentication> oAuth) -> {
                    Assertions.assertTrue(oAuth.isPresent());
                    TrecAuthentication trecAuth = oAuth.get();

                    Assertions.assertEquals("aaaaaa", trecAuth.getSessionId());
                    Assertions.assertEquals(user.getId(), trecAuth.getUser().getId());

                }).verifyComplete();
    }
}
