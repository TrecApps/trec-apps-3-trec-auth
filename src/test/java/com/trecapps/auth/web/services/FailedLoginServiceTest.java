package com.trecapps.auth.web.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.FailedLoginList;
import com.trecapps.auth.webflux.services.FailedLoginServiceAsync;
import com.trecapps.auth.webflux.services.IUserStorageServiceAsync;
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

import java.lang.reflect.Field;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class FailedLoginServiceTest {

    @Mock
    IUserStorageService userStorageService;

    FailedLoginService failedLoginService;

    void setAttribute(Object mockObject, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = FailedLoginService.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(failedLoginService, mockObject);
    }

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        failedLoginService = new FailedLoginService();

        setAttribute(userStorageService, "userStorageService");
        setAttribute(Integer.parseInt("2"), "loginLimit");
        setAttribute(Integer.parseInt("2"), "loginLimitSpan");
        setAttribute("app", "app");
    }

    @Test
    void testAppendFailedLogin() throws JsonProcessingException {
        AppLocker locker = new AppLocker();

        Mockito.doReturn(locker).when(userStorageService).retrieveAppLocker(anyString());
        Assertions.assertEquals(1, failedLoginService.appendFailedLogin("id"));


        Assertions.assertEquals(2, failedLoginService.appendFailedLogin("id"));
    }

    @Test
    void testIsLocked() throws JsonProcessingException {
        Mockito.doReturn(new AppLocker()).when(userStorageService).retrieveAppLocker(anyString());
        Assertions.assertFalse(failedLoginService.isLocked("id"));

        AppLocker locker = new AppLocker();
        Mockito.doReturn(locker).when(userStorageService).retrieveAppLocker(anyString());

        Assertions.assertFalse(failedLoginService.isLocked("id"));

        FailedLoginList loginList = new FailedLoginList();
        loginList.setFailedLogins(List.of(OffsetDateTime.now().minusMinutes(7), OffsetDateTime.now().minusMinutes(5)));

        loginList.setUnlockTime(OffsetDateTime.now().plusMinutes(5));
        locker.getLoginListMap().put("app", loginList);

        Assertions.assertTrue(failedLoginService.isLocked("id"));

        loginList.setUnlockTime(OffsetDateTime.now().minusMinutes(2));
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            AppLocker locker1 = invoke.getArgument(0, AppLocker.class);
            Map<String, FailedLoginList> map = locker1.getLoginListMap();
            FailedLoginList failedLoginList = map.get("app");
            Assertions.assertNotNull(failedLoginList);
            Assertions.assertNull(failedLoginList.getUnlockTime());
            Assertions.assertTrue(failedLoginList.getFailedLogins().isEmpty());
            return null;
        }).when(userStorageService).saveLogins(any(AppLocker.class), anyString());
        Assertions.assertFalse(failedLoginService.isLocked("id"));
    }
}
