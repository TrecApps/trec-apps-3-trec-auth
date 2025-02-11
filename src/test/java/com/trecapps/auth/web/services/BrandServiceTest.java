package com.trecapps.auth.web.services;

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
public class BrandServiceTest {


    private static final String CLIENT_STRING = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0";

    @Mock
    IUserStorageService userStorageService;

    @Mock
    BrandEntryRepo brandEntryRepo;

    JwtTokenService tokenService;
    V2SessionManager sessionManager;

    @Mock
    IFieldEncryptor encryptor;

    @Mock
    TrecAccountRepo trecAccountRepo;
    @Mock
    IJwtKeyHolder jwtKeyHolder;

    @Mock
    FailedLoginService failedLoginService;

    BrandService brandService;

    TcUser user = ObjectTestProvider.getTcUser();

    UUID brandId = UUID.randomUUID();

    void setAttribute(Object mockObject, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = BrandService.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(brandService, mockObject);
    }

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        this.sessionManager = new V2SessionManager(userStorageService, failedLoginService, false);
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


        brandService = new BrandService();

        setAttribute(userStorageService, "userStorageService");
        setAttribute(brandEntryRepo, "brandEntryRepo");
        setAttribute(sessionManager, "sessionManager");
        setAttribute(tokenService, "jwtTokenService");
        setAttribute(trecAccountRepo, "trecAccountRepo");
    }

    @Test
    void testCreateNewBrand(){
        Mockito.doReturn(Optional.empty()).when(userStorageService).getAccountById(anyString());
        String res = this.brandService.createNewBrand(user.getTrecAccount(), "TrecApps");
        Assertions.assertTrue(res.startsWith("500"));


        Mockito.doReturn(Optional.of(user)).when(userStorageService).getAccountById(anyString());
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

        res = brandService.createNewBrand(user.getTrecAccount(), "Trec-Apps");
        Assertions.assertTrue(res.startsWith("200"));
    }

    @Test
    void testIsOwner(){
        Mockito.doReturn(Optional.empty()).when(userStorageService).getBrandById(anyString());
        Mono<Boolean> mono = Mono.just(brandService.isOwner(user.getTrecAccount(), brandId.toString()));

        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();

        TcBrands brand = ObjectTestProvider.getBrand();
        Mockito.doReturn(Optional.of(brand)).when(userStorageService).getBrandById(anyString());
        mono = Mono.just(brandService.isOwner(user.getTrecAccount(), brandId.toString()));
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue).verifyComplete();

        brand.setOwners(new HashSet<>());
        mono = Mono.just(brandService.isOwner(user.getTrecAccount(), brandId.toString()));
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse).verifyComplete();
    }

    @Test
    void testGetBrandList(){
        Mockito.doReturn(Optional.empty()).when(userStorageService).getAccountById(anyString());
        Assertions.assertNull(brandService.getBrandList(user.getTrecAccount()));


        TcBrands brand1 = ObjectTestProvider.getBrand();
        brand1.setId(brandId.toString());
        UUID id2 = UUID.randomUUID();

        TcBrands brand2 = new TcBrands();
        brand2.setId(id2.toString());
        brand2.setOwners(new HashSet<>(List.of("id")));
        brand2.setName("Coffee-shop");

        user.setBrands(new HashSet<>(List.of(brandId.toString(), id2.toString())));

        Mockito.doReturn(Optional.of(user)).when(userStorageService).getAccountById(anyString());
        Mockito.doReturn(Optional.of(BrandEntry.getInstance(brand1, "id")))
                .when(brandEntryRepo).findById(brandId.toString());
        Mockito.doReturn(Optional.of(BrandEntry.getInstance(brand2, "id")))
                .when(brandEntryRepo).findById(id2.toString());

        Mono<List<BrandEntry>> mono = Mono.just(brandService.getBrandList(user.getTrecAccount()));
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

        Mockito.doReturn(Optional.empty()).when(userStorageService).getBrandById(anyString());

        TcBrands mono = brandService.getBrandById(brandId.toString(), user.getTrecAccount());

        Assertions.assertNull(mono);

        Mockito.doReturn(Optional.of(brand1)).when(userStorageService).getBrandById(anyString());

        mono = brandService.getBrandById(brandId.toString(), user.getTrecAccount());
        Assertions.assertNotNull(mono);
        Assertions.assertTrue(mono.getOwners().isEmpty());

        brand1.setOwners(new HashSet<>(List.of("id")));
        mono = brandService.getBrandById(brandId.toString(), user.getTrecAccount());

        Assertions.assertNotNull(mono);
        Assertions.assertTrue(mono.getOwners().contains("id"));
    }

    @Test
    void testLoginAsBrand(){
        TcBrands brand1 = ObjectTestProvider.getBrand();
        brand1.setId(brandId.toString());
        brand1.setOwners(new HashSet<>(List.of("altIds")));

        Mockito.doReturn(Optional.of(brand1)).when(userStorageService).getBrandById(anyString());

        TrecAuthentication auth = new TrecAuthentication(user);
        auth.setSessionId("aaaaaa");

        LoginToken mono =
                brandService.loginAsBrand(
                        auth,
                        brandId.toString(),
                        CLIENT_STRING,
                        auth.getSessionId(),
                        false,
                        "app");
        Assertions.assertNull(mono);

        brand1.setOwners(new HashSet<>(List.of("id")));
        Mockito.doReturn(Optional.of(brand1)).when(userStorageService).getBrandById(brandId.toString());

        // now set up sessions
        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app",null);
        sessionV2.setDeviceId("aaaaaa");

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);
        Mockito.doReturn(sessionListV2).when(userStorageService).retrieveSessionList(anyString());


        mono = brandService.loginAsBrand(auth,
                brandId.toString(),
                CLIENT_STRING,
                auth.getSessionId(),
                false,
                "app");

        Assertions.assertNotNull(mono);
        Assertions.assertNotNull(mono.getAccess_token());
    }

    @Test
    void testAssignOwnerNonExist(){
        TcUser user1 = new TcUser();
        user1.setId("id2");
        user1.setUserProfile("JaneDoe");
        user1.setDisplayName("Jane Doe");

        TcBrands brand = ObjectTestProvider.getBrand();
        brand.setOwners(new HashSet<>(List.of("id")));


        // Assume brand exists but user doesn't
        Mockito.lenient().doReturn(true).doReturn(false).when(brandEntryRepo).existsById(brandId.toString());
        Mockito.lenient().doReturn(false).doReturn(true).when(trecAccountRepo).existsById("id2");

        Mono<Boolean> mono = Mono.just(brandService.assignOwner(user.getTrecAccount(), "id2", brandId.toString()));
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertFalse)
                .verifyComplete();

        // Assume user exist but brand doesn't

        mono = Mono.just(brandService.assignOwner(user.getTrecAccount(), "id2", brandId.toString()));
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

        Mockito.doReturn(Optional.of(brand)).when(userStorageService).getBrandById(anyString());

        Mockito.doReturn(true).when(brandEntryRepo).existsById(anyString());
        Mockito.doReturn(true).when(trecAccountRepo).existsById(anyString());

        Mockito.doReturn(Optional.of(user1)).when(userStorageService).getAccountById("id2");

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

        Mono<Boolean> mono = Mono.just(brandService.assignOwner(user.getTrecAccount(), "id2", brandId.toString()));
        StepVerifier.create(mono)
                .consumeNextWith(Assertions::assertTrue)
                .verifyComplete();
    }
}
