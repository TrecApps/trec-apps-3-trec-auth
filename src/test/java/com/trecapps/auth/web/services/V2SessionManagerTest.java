package com.trecapps.auth.web.services;

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

import java.time.OffsetDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class V2SessionManagerTest {

    @Mock
    IUserStorageService userStorageService;

    V2SessionManager sessionManager;

    TcUser user = ObjectTestProvider.getTcUser();
    @Mock
    FailedLoginService failedLoginService;

    @BeforeEach
    void setUp(){
        this.sessionManager = new V2SessionManager(userStorageService, failedLoginService,false);
    }

    @Test
    void testAddSession(){
        Mockito.doReturn(new SessionListV2()).when(userStorageService).retrieveSessionList(anyString());

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
            return null;
        }).when(userStorageService).saveSessions(any(SessionListV2.class), anyString());

        TokenTime tokenTime = this.sessionManager.addSession(
                "app",
                user.getId(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                false);

        Assertions.assertNull(tokenTime.getExpiration());
        Assertions.assertEquals(sessionId.get(), tokenTime.getSession());
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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

        this.sessionManager.updateSessionExpiration(user.getId(), "cccccc", time);

        SessionV2 session = sessionListV2.getSessionById("cccccc");
        Assertions.assertEquals(session.getExpiration(), time);
    }

    @Test
    void testSetBrand(){
        SessionApp sessionApp = new SessionApp();
        sessionApp.setApp("Coffeeshop");

        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setApps(List.of(sessionApp));
        sessionV2.setDeviceId("cccccc");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

        this.sessionManager.setBrand(user.getId(), "cccccc", "brandId", "Coffeeshop", false);

        SessionV2 session = sessionListV2.getSessionById("cccccc");
        Assertions.assertFalse(session.getApps().isEmpty());
        SessionApp sessionApp1 = session.getApps().get(0);

        Assertions.assertEquals("Coffeeshop", sessionApp1.getApp());
        Assertions.assertNull(sessionApp1.getBrandId());


        this.sessionManager.setBrand(user.getId(), "cccccc", "brandId", "Coffeeshop");

        SessionV2 session1 = sessionListV2.getSessionById("cccccc");
        Assertions.assertFalse(session1.getApps().isEmpty());
        SessionApp sessionApp2 = session1.getApps().get(0);

        Assertions.assertEquals("Coffeeshop", sessionApp2.getApp());
        Assertions.assertEquals("brandId",sessionApp2.getBrandId());
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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

        List<SessionV2> list = this.sessionManager.getSessionList(user.getId());

        Assertions.assertEquals(1, list.size());
        Assertions.assertEquals("cccccc", list.get(0).getDeviceId());
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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

        String brandId = sessionManager.getBrand(user.getId(), "cccccc", "Coffeeshop");

        Assertions.assertTrue(brandId.isEmpty());
    }

    @Test
    void testRemoveSession(){
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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());


        sessionManager.removeSession(user.getId(), "cccccc");

        Assertions.assertEquals(1, sessionListV2.getSessions().size());
        sessionV2 = sessionListV2.getSessions().get(0);
        Assertions.assertEquals("dddddd", sessionV2.getDeviceId());
    }

    @Test
    void testRemoveSessions(){
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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());


        sessionManager.removeSessions(user.getId(), List.of("cccccc", "eeeeee"));

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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            SessionListV2 list = invoke.getArgument(0, SessionListV2.class);
            Assertions.assertEquals(1, list.getSessions().size());
            SessionV2 sessionV2_1 = list.getSessions().get(0);
            List<String> blockedApps = sessionV2_1.getBlockedApps();
            Assertions.assertEquals(1, blockedApps.size());
            Assertions.assertEquals("Watercooler", blockedApps.get(0));
            return null;
        }).when(userStorageService).saveSessions(any(SessionListV2.class), anyString());

        sessionManager.blockApp(user.getId(), "cccccc", "Watercooler");



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

        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());

        Mockito.doReturn(Boolean.FALSE).when(failedLoginService).isLocked(anyString());

        boolean valid = sessionManager.isValidSession(user.getId(), "Coffeeshop", "cccccc");
        Assertions.assertTrue(valid);

        valid = sessionManager.isValidSession(user.getId(), "Coffeeshop", "aaaaaa");
        Assertions.assertFalse(valid);

        valid = sessionManager.isValidSession(user.getId(), "Watercooler", "cccccc");
        Assertions.assertFalse(valid);

        sessionV2.setExpiration(OffsetDateTime.now().minusSeconds(10));
        valid = sessionManager.isValidSession(user.getId(), "Coffeeshop", "cccccc");
        Assertions.assertFalse(valid);
    }
}
