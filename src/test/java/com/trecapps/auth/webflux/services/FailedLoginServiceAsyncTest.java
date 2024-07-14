package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.FailedLoginList;
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
public class FailedLoginServiceAsyncTest {

    @Mock
    IUserStorageServiceAsync userStorageService;

    FailedLoginServiceAsync failedLoginService;

    void setAttribute(Object mockObject, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = FailedLoginServiceAsync.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(failedLoginService, mockObject);
    }

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        failedLoginService = new FailedLoginServiceAsync();

        setAttribute(userStorageService, "userStorageService");
        setAttribute(Integer.parseInt("2"), "loginLimit");
        setAttribute(Integer.parseInt("2"), "loginLimitSpan");
        setAttribute("app", "app");
    }

    @Test
    void testAppendFailedLogin(){
        Mockito.doReturn(Mono.just(Optional.empty())).when(userStorageService).retrieveAppLocker(anyString());

        Mono<Integer> mono = failedLoginService.appendFailedLogin("id");
        StepVerifier.create(mono)
                .consumeNextWith((Integer i) -> Assertions.assertEquals(0, i))
                .verifyComplete();

        AppLocker locker = new AppLocker();

        Mockito.doReturn(Mono.just(Optional.of(locker))).when(userStorageService).retrieveAppLocker(anyString());

        mono = failedLoginService.appendFailedLogin("id");
        StepVerifier.create(mono)
                .consumeNextWith((Integer i) -> Assertions.assertEquals(1, i))
                .verifyComplete();

        mono = failedLoginService.appendFailedLogin("id");
        StepVerifier.create(mono)
                .consumeNextWith((Integer i) -> Assertions.assertEquals(2, i))
                .verifyComplete();
    }

    @Test
    void testIsLocked(){
        Mockito.doReturn(Mono.just(Optional.empty())).when(userStorageService).retrieveAppLocker(anyString());

        Mono<Boolean> mono = failedLoginService.isLocked("id");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue)
                .verifyComplete();

        AppLocker locker = new AppLocker();
        Mockito.doReturn(Mono.just(Optional.of(locker))).when(userStorageService).retrieveAppLocker(anyString());

        mono = failedLoginService.isLocked("id");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse)
                .verifyComplete();

        FailedLoginList loginList = new FailedLoginList();
        loginList.setFailedLogins(List.of(OffsetDateTime.now().minusMinutes(7), OffsetDateTime.now().minusMinutes(5)));

        loginList.setUnlockTime(OffsetDateTime.now().plusMinutes(5));
        locker.getLoginListMap().put("app", loginList);

        mono = failedLoginService.isLocked("id");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue)
                .verifyComplete();

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

        mono = failedLoginService.isLocked("id");
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse)
                .verifyComplete();
    }
}
