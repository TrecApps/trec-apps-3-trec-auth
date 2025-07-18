package com.trecapps.auth.webflux.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.models.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class V2SessionManagerAsyncTest {

    @Mock
    IUserStorageServiceAsync userStorageService;
    @Mock
    FailedLoginServiceAsync failedLoginServiceAsync;

    V2SessionManagerAsync sessionManager;

    TcUser user = ObjectTestProvider.getTcUser();

    @BeforeEach
    void setUp(){
        this.sessionManager = new V2SessionManagerAsync(userStorageService, failedLoginServiceAsync, false);
    }

    @Test
    void testAddSession(){
        Mockito.doReturn(Mono.just(new SessionListV2())).when(userStorageService).retrieveSessionList(anyString());

        AtomicReference<String> sessionId = new AtomicReference<>();
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            SessionListV2 sessionList = invoke.getArgument(0, SessionListV2.class);
            String userId = invoke.getArgument(1, String.class);

            Assertions.assertEquals(1, sessionList.getSessions().size());
            Assertions.assertEquals(user.getId(), userId);

            SessionV2 sessionV2 = sessionList.getSessions().get(0);
            sessionId.set(sessionV2.getDeviceId());
            String devices = sessionV2.getDeviceInfo();

            Assertions.assertTrue(devices.contains("Browser: Mozilla FireFox"));
            return Mono.empty();
        }).when(userStorageService).saveSessionsMono(any(SessionListV2.class), anyString());

        Mono<TokenTime> mono = this.sessionManager.addSession(
                "app",
                user.getId(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                false);

        StepVerifier.create(mono)
                .consumeNextWith((TokenTime tokenTime) -> {
                    Assertions.assertNull(tokenTime.getExpiration());
                    Assertions.assertEquals(sessionId.get(), tokenTime.getSession());
                }).verifyComplete();
    }

    @Test
    void testUpdateSessionExpiration(){
        OffsetDateTime time = OffsetDateTime.now();

        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        Mono<SessionListV2> mono = this.sessionManager.updateSessionExpiration(user.getId(), "cccccc", time);

        StepVerifier.create(mono)
                .consumeNextWith((SessionListV2 list) -> {
                    SessionV2 session = list.getSessionById("cccccc");
                    Assertions.assertEquals(session.getExpiration(), time);
                }).verifyComplete();
    }

    @Test
    void testSetBrandMono(){
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        Mono<SessionListV2> mono = this.sessionManager.setBrandMono(user.getId(), "cccccc", "brandId", "Coffeeshop", false);

        StepVerifier.create(mono)
                .consumeNextWith((SessionListV2 list) -> {
                    SessionV2 session = list.getSessionById("cccccc");
                    Assertions.assertFalse(session.getApps().isEmpty());
                    SessionApp sessionApp1 = session.getApps().get(0);

                    Assertions.assertEquals("Coffeeshop", sessionApp1.getApp());
                    Assertions.assertNull(sessionApp1.getBrandId());
                });

        mono = this.sessionManager.setBrandMono(user.getId(), "cccccc", "brandId", "Coffeeshop");

        StepVerifier.create(mono)
                .consumeNextWith((SessionListV2 list) -> {
                    SessionV2 session = list.getSessionById("cccccc");
                    Assertions.assertFalse(session.getApps().isEmpty());
                    SessionApp sessionApp1 = session.getApps().get(0);

                    Assertions.assertEquals("Coffeeshop", sessionApp1.getApp());
                    Assertions.assertEquals("brandId",sessionApp1.getBrandId());
                }).verifyComplete();
    }

    @Test
    void testGetSessionList() {
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        Mono<List<SessionV2>> mono = this.sessionManager.getSessionList(user.getId());

        StepVerifier.create(mono)
                .consumeNextWith((List<SessionV2> list) -> {
                    Assertions.assertEquals(1, list.size());
                    Assertions.assertEquals("cccccc", list.get(0).getDeviceId());
                }).verifyComplete();
    }

    @Test
    void testGetBrand() {
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        Mono<String> mono = sessionManager.getBrand(user.getId(), "cccccc", "Coffeeshop");

        StepVerifier.create(mono)
                .consumeNextWith((String brandId) -> {
                    Assertions.assertTrue(brandId.isEmpty());
                }).verifyComplete();
    }

    @Test
    void testRemoveSessionMono(){
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        sessionApp = new SessionApp();
        sessionApp.setApp("WaterCooler");
        sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("dddddd");
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());
        Mockito.doReturn(Mono.empty()).when(userStorageService).saveSessionsMono(any(SessionListV2.class), anyString());


        Mono<Void> mono = sessionManager.removeSessionMono(user.getId(), "cccccc");

        StepVerifier.create(mono)
                .verifyComplete();

        Assertions.assertEquals(1, sessionListV2.getSessions().size());
        sessionV2 = sessionListV2.getSessions().get(0);
        Assertions.assertEquals("dddddd", sessionV2.getDeviceId());
    }

    @Test
    void testRemoveSessionListMono(){
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        sessionApp = new SessionApp();
        sessionApp.setApp("WaterCooler");
        sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("dddddd");
        sessionListV2.getSessions().add(sessionV2);
        sessionApp = new SessionApp();
        sessionApp.setApp("Falsehoods");
        sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("eeeeee");
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());
        Mockito.doReturn(Mono.empty()).when(userStorageService).saveSessionsMono(any(SessionListV2.class), anyString());


        Mono<Void> mono = sessionManager.removeSessionMono(user.getId(), List.of("cccccc", "eeeeee"));

        StepVerifier.create(mono)
                .verifyComplete();

        Assertions.assertEquals(1, sessionListV2.getSessions().size());
        sessionV2 = sessionListV2.getSessions().get(0);
        Assertions.assertEquals("dddddd", sessionV2.getDeviceId());
    }

    @Test
    void testBlockApp() {
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        Mono<SessionListV2> mono = sessionManager.blockApp(user.getId(), "cccccc", "Watercooler");

        StepVerifier.create(mono)
                .consumeNextWith((SessionListV2 list) -> {
                    Assertions.assertEquals(1, sessionListV2.getSessions().size());
                    SessionV2 sessionV2_1 = list.getSessions().get(0);
                    List<String> blockedApps = sessionV2_1.getBlockedApps();
                    Assertions.assertEquals(1, blockedApps.size());
                    Assertions.assertEquals("Watercooler", blockedApps.get(0));
                }).verifyComplete();
    }

    @Test
    void testIsValidSession(){
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());
        Mockito.doReturn(Mono.just(Boolean.FALSE)).when(failedLoginServiceAsync).isLocked(anyString());

        Mono<Boolean> mono = sessionManager.isValidSession(user.getId(), "Coffeeshop", "cccccc");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue).verifyComplete();

        mono = sessionManager.isValidSession(user.getId(), "Coffeeshop", "aaaaaa");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();

        mono = sessionManager.isValidSession(user.getId(), "Watercooler", "cccccc");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();

        sessionV2.setExpiration(OffsetDateTime.now().minusSeconds(10));
        mono = sessionManager.isValidSession(user.getId(), "Coffeeshop", "cccccc");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();
    }
}
