package com.trecapps.auth.webflux.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.RSATestHelper;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.models.secondary.BrandEntry;
import com.trecapps.auth.common.repos.primary.TrecAccountRepo;
import com.trecapps.auth.common.repos.secondary.BrandEntryRepo;
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
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class BrandServiceAsyncTest {

    private static final String CLIENT_STRING = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0";

    @Mock
    IUserStorageServiceAsync userStorageService;

    @Mock
    BrandEntryRepo brandEntryRepo;

    JwtTokenServiceAsync tokenService;
    V2SessionManagerAsync sessionManager;

    @Mock
    IFieldEncryptor encryptor;

    @Mock
    TrecAccountRepo trecAccountRepo;
    @Mock
    IJwtKeyHolder jwtKeyHolder;
    @Mock
    FailedLoginServiceAsync failedLoginServiceAsync;

    BrandServiceAsync brandService;

    TcUser user = ObjectTestProvider.getTcUser();

    UUID brandId = UUID.randomUUID();

    void setAttribute(Object mockObject, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = BrandServiceAsync.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(brandService, mockObject);
    }

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        this.sessionManager = new V2SessionManagerAsync(userStorageService, failedLoginServiceAsync,false);
        Mockito.doReturn(RSATestHelper.publicKeyValue).when(jwtKeyHolder).getPublicKey(0);
        Mockito.doReturn(RSATestHelper.privateKeyValue.replace('|', '\n')).when(jwtKeyHolder).getPrivateKey(0);
        tokenService = new JwtTokenServiceAsync(
                userStorageService,
                sessionManager,
                jwtKeyHolder,
                new JwtKeyArray(1),
                "app",
                1
        );


        brandService = new BrandServiceAsync();

        setAttribute(userStorageService, "userStorageService");
        setAttribute(brandEntryRepo, "brandEntryRepo");
        setAttribute(sessionManager, "sessionManager");
        setAttribute(tokenService, "jwtTokenService");
        setAttribute(trecAccountRepo, "trecAccountRepo");
    }

    @Test
    void testCreateNewBrand(){
        Mockito.doReturn(Mono.just(Optional.empty())).when(userStorageService).getAccountById(anyString());
        Mono<String> mono = this.brandService.createNewBrand(user.getTrecAccount(), "TrecApps");
        StepVerifier.create(mono)
                .consumeNextWith((String res) -> Assertions.assertTrue(res.startsWith("500")))
                .verifyComplete();


        Mockito.doReturn(Mono.just(Optional.of(user))).when(userStorageService).getAccountById(anyString());
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TcBrands obj = invoke.getArgument(0, TcBrands.class);

            Assertions.assertTrue(obj.getOwners().contains(user.getId()));
            Assertions.assertEquals(1, obj.getOwners().size());

            return Mono.empty();
        }).when(userStorageService).saveBrand(any(TcBrands.class));
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TcUser obj = invoke.getArgument(0, TcUser.class);
            Assertions.assertTrue(obj.getBrands().contains(brandId.toString()));
            Assertions.assertEquals(1, obj.getBrands().size());

            return Mono.empty();
        }).when(userStorageService).saveUser(any(TcUser.class));

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            BrandEntry obj = invoke.getArgument(0, BrandEntry.class);
            obj.setId(brandId.toString());
            return obj;
        }).when(brandEntryRepo).save(any(BrandEntry.class));

        mono = brandService.createNewBrand(user.getTrecAccount(), "Trec-Apps");
        StepVerifier.create(mono)
                .consumeNextWith((String res) -> Assertions.assertTrue(res.startsWith("200")))
                .verifyComplete();
    }

    @Test
    void testIsOwner(){
        Mockito.doReturn(Mono.just(Optional.empty())).when(userStorageService).getBrandById(anyString());
        Mono<Boolean> mono = brandService.isOwner(user.getTrecAccount(), brandId.toString());

        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();

        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(Mono.just(Optional.of(brand))).when(userStorageService).getBrandById(anyString());
        mono = brandService.isOwner(user.getTrecAccount(), brandId.toString());
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue).verifyComplete();

        brand.setOwners(new HashSet<>());
        mono = brandService.isOwner(user.getTrecAccount(), brandId.toString());
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();
    }

    @Test
    void testGetBrandList(){
        Mockito.doReturn(Mono.just(Optional.empty())).when(userStorageService).getAccountById(anyString());
        Mono<List<BrandEntry>> mono = brandService.getBrandList(user.getTrecAccount());
        StepVerifier.create(mono)
                .consumeNextWith((List<BrandEntry> entries) -> {
                    Assertions.assertTrue(entries.isEmpty());
                })
                .verifyComplete();


        TcBrands brand1 = ObjectTestProvider.getBrand();
        brand1.setId(brandId.toString());
        UUID id2 = UUID.randomUUID();

        TcBrands brand2 = new TcBrands();
        brand2.setId(id2.toString());
        brand2.setOwners(new HashSet<>(List.of("id")));
        brand2.setName("Coffee-shop");

        user.setBrands(new HashSet<>(List.of(brandId.toString(), id2.toString())));

        Mockito.doReturn(Mono.just(Optional.of(user))).when(userStorageService).getAccountById(anyString());
        Mockito.doReturn(Optional.of(BrandEntry.getInstance(brand1, "id")))
                .when(brandEntryRepo).findById(brandId.toString());
        Mockito.doReturn(Optional.of(BrandEntry.getInstance(brand2, "id")))
                .when(brandEntryRepo).findById(id2.toString());

        mono = brandService.getBrandList(user.getTrecAccount());
        StepVerifier.create(mono)
                .consumeNextWith((List<BrandEntry> entries) -> {
                    Assertions.assertEquals(2, entries.size());
                }).verifyComplete();
    }

    @Test
    void testGetBrandById(){
        TcBrands brand1 = ObjectTestProvider.getBrand();
        brand1.setId(brandId.toString());
        brand1.setOwners(new HashSet<>(List.of("altIds")));

        Mockito.doReturn(Mono.just(Optional.empty())).when(userStorageService).getBrandById(anyString());

        Mono<Optional<TcBrands>> mono = brandService.getBrandById(brandId.toString(), user.getTrecAccount());
        StepVerifier.create(mono)
                        .consumeNextWith((Optional<TcBrands> brands) -> {
                            Assertions.assertTrue(brands.isEmpty());
                        }).verifyComplete();


        Mockito.doReturn(Mono.just(Optional.of(brand1))).when(userStorageService).getBrandById(anyString());

        mono = brandService.getBrandById(brandId.toString(), user.getTrecAccount());
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TcBrands> brands) -> {
                    Assertions.assertTrue(brands.isPresent());
                    TcBrands tcBrand = brands.get();
                    Assertions.assertTrue(tcBrand.getOwners().isEmpty());
                }).verifyComplete();

        brand1.setOwners(new HashSet<>(List.of("id")));
        mono = brandService.getBrandById(brandId.toString(), user.getTrecAccount());
        StepVerifier.create(mono)
                .consumeNextWith((Optional<TcBrands> brands) -> {
                    Assertions.assertTrue(brands.isPresent());
                    TcBrands tcBrand = brands.get();
                    Assertions.assertTrue(tcBrand.getOwners().contains("id"));
                }).verifyComplete();
    }

    @Test
    void testLoginAsBrand(){
        TcBrands brand1 = ObjectTestProvider.getBrand();
        brand1.setId(brandId.toString());
        brand1.setOwners(new HashSet<>(List.of("altIds")));

        Mockito.doReturn(Mono.just(Optional.of(brand1))).when(userStorageService).getBrandById(anyString());

        TrecAuthentication auth = new TrecAuthentication(user);
        auth.setSessionId("aaaaaa");

        Mono<Optional<LoginToken>> mono =
                brandService.loginAsBrand(
                        auth,
                        brandId.toString(),
                        CLIENT_STRING,
                        auth.getSessionId(),
                        false,
                        "app");
        StepVerifier.create(mono)
                        .consumeNextWith((Optional<LoginToken> token) -> {
                            Assertions.assertTrue(token.isEmpty());
                        });

        brand1.setOwners(new HashSet<>(List.of("id")));
        Mockito.doReturn(Mono.just(Optional.of(brand1))).when(userStorageService).getBrandById(brandId.toString());

        // now set up sessions
        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setDeviceId("aaaaaa");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);
        Mockito.doReturn(Mono.just(sessionListV2)).when(userStorageService).retrieveSessionList(anyString());

        mono = brandService.loginAsBrand(auth,
                brandId.toString(),
                CLIENT_STRING,
                auth.getSessionId(),
                false,
                "app");

        StepVerifier.create(mono)
                .consumeNextWith((Optional<LoginToken> token) -> {
                    Assertions.assertTrue(token.isPresent());
                    LoginToken loginToken = token.get();
                    Assertions.assertNotNull(loginToken.getAccess_token());
                }).verifyComplete();
    }

    @Test
    void testAssignOwnerNonExist(){
        TcUser user1 = new TcUser();
        user1.setId("id2");
        user1.setUserProfile("JaneDoe");
        user1.setDisplayName("Jane Doe");

        TcBrands brand = ObjectTestProvider.getBrand();
        brand.setOwners(new HashSet<>(List.of("id")));

        Mockito.doReturn(Mono.just(Optional.of(brand))).when(userStorageService).getBrandById(anyString());


        // Assume brand exists but user doesn't
        Mockito.lenient().doReturn(true).doReturn(false).when(brandEntryRepo).existsById(brandId.toString());
        Mockito.lenient().doReturn(false).doReturn(true).when(trecAccountRepo).existsById("id2");

        Mono<Boolean> mono = brandService.assignOwner(user.getTrecAccount(), "id2", brandId.toString());
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse)
                .verifyComplete();

        // Assume user exist but brand doesn't

        mono = brandService.assignOwner(user.getTrecAccount(), "id2", brandId.toString());
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse)
                .verifyComplete();
    }

    @Test
    void testAssignOwnerSuccess(){
        TcUser user1 = new TcUser();
        user1.setId("id2");
        user1.setUserProfile("JaneDoe");
        user1.setDisplayName("Jane Doe");

        TcBrands brand = ObjectTestProvider.getBrand();
        brand.setOwners(new HashSet<>(List.of("id")));

        Mockito.doReturn(Mono.just(Optional.of(brand))).when(userStorageService).getBrandById(anyString());

        Mockito.doReturn(true).when(brandEntryRepo).existsById(anyString());
        Mockito.doReturn(true).when(trecAccountRepo).existsById(anyString());

        Mockito.doReturn(Mono.just(Optional.of(user1))).when(userStorageService).getAccountById("id2");

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TcBrands obj = invoke.getArgument(0, TcBrands.class);

            Assertions.assertTrue(obj.getOwners().contains(user.getId()));
            Assertions.assertEquals(2, obj.getOwners().size());
            Assertions.assertTrue(obj.getOwners().contains("id2"));

            return Mono.empty();
        }).when(userStorageService).saveBrand(any(TcBrands.class));
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TcUser obj = invoke.getArgument(0, TcUser.class);
            Assertions.assertTrue(obj.getBrands().contains(brandId.toString()));
            Assertions.assertEquals(1, obj.getBrands().size());

            return Mono.empty();
        }).when(userStorageService).saveUser(any(TcUser.class));

        Mono<Boolean> mono = brandService.assignOwner(user.getTrecAccount(), "id2", brandId.toString());
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue)
                .verifyComplete();
    }
}
