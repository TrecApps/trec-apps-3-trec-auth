package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.models.primary.TrecAccount;
import com.trecapps.auth.common.models.secondary.UserSalt;
import com.trecapps.auth.webflux.repos.primary.TrecAccountRepo;
import com.trecapps.auth.webflux.repos.secondary.UserSaltRepo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCrypt;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Field;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class TrecAccountServiceAsyncTest {

    @Mock
    TrecAccountRepo trecRepo;

    @Mock
    UserSaltRepo saltRepo;

    @Mock
    FailedLoginServiceAsync failedLoginService;

    @Mock
    IFieldEncryptor encryptor;

    TrecAccountServiceAsync trecAccountService;

    TrecAccount account = new TrecAccount();

    String oldBCrypt;

    String saltValue = BCrypt.gensalt();//"$2saltsaltsaltsaltsaltsaltsalt";

    void setAttribute(Object mockObject, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = TrecAccountServiceAsync.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(trecAccountService, mockObject);
    }

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        trecAccountService = new TrecAccountServiceAsync();
        setAttribute(trecRepo, "trecRepo");
        setAttribute(saltRepo, "saltRepo");
        setAttribute(failedLoginService, "failedLoginService");
        setAttribute(encryptor, "encryptor");
        setAttribute(Integer.parseInt("2"), "loginLimit");


        account.setId("1234");
        account.setUsername("jDoe");

        oldBCrypt = BCrypt.hashpw("oldPassword", saltValue);
    }

    @Test
    void testUserNameExists(){
        Mockito.doReturn(true).when(trecRepo).existsByUsername(anyString());
        Mono<Boolean> tMono = trecAccountService.userNameExists("jDoe");
        StepVerifier.create(tMono)
                .consumeNextWith(Assertions::assertTrue)
                .verifyComplete();

        Mockito.doReturn(false).when(trecRepo).existsByUsername(anyString());
        Mono<Boolean> fMono = trecAccountService.userNameExists("jDoe");

        StepVerifier.create(fMono)
                .consumeNextWith(Assertions::assertFalse)
                .verifyComplete();
    }

    @Test
    void testSaveNewAccount(){
        Mockito.doReturn(true).when(trecRepo).existsByUsername(anyString());
        Mono<Optional<TrecAccount>> tMono = trecAccountService.saveNewAccount(account);
        StepVerifier.create(tMono)
                .consumeNextWith((Optional<TrecAccount> oAccount) -> Assertions.assertTrue(oAccount.isEmpty()))
                .verifyComplete();

        account.setPasswordHash("password");

        Mockito.doReturn(false).when(trecRepo).existsByUsername(anyString());

        Mockito.doAnswer((InvocationOnMock invoke) -> {
          TrecAccount account1 = invoke.getArgument(0, TrecAccount.class);
          Assertions.assertNull(account1.getId());
          Assertions.assertNull(account1.getPasswordHash());

          account1.setId("1234");
          return account1;
        }).doAnswer((InvocationOnMock invoke) -> {
                    TrecAccount account1 = invoke.getArgument(0, TrecAccount.class);
                    Assertions.assertNotNull(account1.getId());
                    Assertions.assertEquals("1234", account1.getId());
                    Assertions.assertNotNull(account1.getPasswordHash());

                    return account1;
        }).when(trecRepo).save(any(TrecAccount.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> invoke.getArgument(0, UserSalt.class))
                .when(encryptor).encrypt(any(UserSalt.class));

        Mono<Optional<TrecAccount>> fMono = trecAccountService.saveNewAccount(account);
        StepVerifier.create(fMono)
                .consumeNextWith((Optional<TrecAccount> oAccount) ->{
                    Assertions.assertTrue(oAccount.isPresent());
                    TrecAccount trecAccount = oAccount.get();
                    Assertions.assertNotNull(trecAccount.getId());
                    Assertions.assertEquals("1234", trecAccount.getId());
                    Assertions.assertNotNull(trecAccount.getPasswordHash());
                })
                .verifyComplete();
    }

    @Test
    void testGetAccountById(){
        Mockito.doReturn(Optional.of(account)).when(trecRepo).findById(anyString());
        Optional<TrecAccount> tMono = trecAccountService.getAccountById("jDoe");
        Assertions.assertTrue(tMono.isPresent());

        Mockito.doReturn(Optional.empty()).when(trecRepo).findById(anyString());
        Optional<TrecAccount> fMono = trecAccountService.getAccountById("jDoe");

        Assertions.assertTrue(fMono.isEmpty());
    }



    @Test
    void testChangePassword(){
        Mockito.doReturn(Optional.empty()).when(trecRepo).findById(anyString());
        Assertions.assertFalse(trecAccountService.changePassword(account, "oldPassword", "newPassword"));

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TrecAccount account1 = new TrecAccount();
            account1.setId(account.getId());
            account1.setUsername(account.getUsername());
            account1.setPasswordHash(oldBCrypt);
            return Optional.of(account1);
        }).when(trecRepo).findById(anyString());

        Mockito.doReturn(Optional.empty()).when(saltRepo).findById(anyString());
        Assertions.assertFalse(trecAccountService.changePassword(account, "oldPassword", "newPassword"));

        Mockito.doAnswer((InvocationOnMock invoke) -> invoke.getArgument(0, UserSalt.class))
                .when(encryptor).decrypt(any(UserSalt.class));


        UserSalt mockSalt = new UserSalt("id", saltValue);
        Mockito.doReturn(Optional.of(mockSalt)).when(saltRepo).findById(anyString());
        Assertions.assertFalse(trecAccountService.changePassword(account, "oldPasswordWrong", "newPassword"));

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TrecAccount account1 = invoke.getArgument(0, TrecAccount.class);
            Assertions.assertNotNull(account1.getPasswordHash());
            Assertions.assertNotEquals(oldBCrypt, account1.getPasswordHash());
            return account1;
        }).when(trecRepo).save(any(TrecAccount.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            UserSalt salt = invoke.getArgument(0, UserSalt.class);
            String newSalt = salt.getSalt();
            Assertions.assertNotNull(newSalt);
            Assertions.assertNotEquals(saltValue, newSalt);
            return salt;
        }).when(saltRepo).save(any(UserSalt.class));
        Mockito.doAnswer((InvocationOnMock invoke) -> invoke.getArgument(0, UserSalt.class))
                .when(encryptor).encrypt(any(UserSalt.class));

        Assertions.assertTrue(trecAccountService.changePassword(account, "oldPassword", "newPassword"));

    }

    @Test
    void testLogInUsername(){
        Mockito.doReturn(false).when(trecRepo).existsByUsername(anyString());
        Mono<Optional<TrecAccount>> mono = trecAccountService.logInUsername("jDoe", "oldPassword", "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TrecAccount> oAccount) -> Assertions.assertTrue(oAccount.isEmpty()))
                .verifyComplete();

        Mockito.doAnswer((InvocationOnMock invoke) -> invoke.getArgument(0, UserSalt.class))
                .when(encryptor).decrypt(any(UserSalt.class));

        account.setPasswordHash(oldBCrypt);
        Mockito.doReturn(true).when(trecRepo).existsByUsername(anyString());
        Mockito.doReturn(account).when(trecRepo).findByUsername(anyString());

        // Test with locked account
        UserSalt userSalt = new UserSalt("id", saltValue);
        Mockito.doReturn(Optional.of(userSalt)).when(saltRepo).findById(anyString());
        Mockito.doReturn(Mono.just(true)).when(failedLoginService).isLocked(anyString());
        mono = trecAccountService.logInUsername("jDoe", "oldPassword", "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TrecAccount> oAccount) -> {
                    Assertions.assertTrue(oAccount.isPresent());
                    Assertions.assertTrue(oAccount.get().isInvalid());
                })
                .verifyComplete();

        // Now do two failed login attempts
        Mockito.doReturn(Mono.just(false)).when(failedLoginService).isLocked(anyString());
        Mockito.doReturn(Mono.just(1)).doReturn(Mono.just(2))
                .when(failedLoginService).appendFailedLogin(anyString());

        mono = trecAccountService.logInUsername("jDoe", "oldPasswordWrong", "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TrecAccount> oAccount) -> {
                    Assertions.assertTrue(oAccount.isEmpty());
                })
                .verifyComplete();
        mono = trecAccountService.logInUsername("jDoe", "oldPasswordWrong", "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TrecAccount> oAccount) -> {
                    Assertions.assertTrue(oAccount.isPresent());
                    Assertions.assertTrue(oAccount.get().isInvalid());
                })
                .verifyComplete();

        // Succeed
        mono = trecAccountService.logInUsername("jDoe", "oldPassword", "app");
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TrecAccount> oAccount) -> {
                    Assertions.assertTrue(oAccount.isPresent());
                    Assertions.assertFalse(oAccount.get().isInvalid());
                })
                .verifyComplete();
    }
}
