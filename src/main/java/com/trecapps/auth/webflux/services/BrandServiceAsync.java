package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.models.primary.TrecAccount;
import com.trecapps.auth.common.models.secondary.BrandEntry;
import com.trecapps.auth.webflux.repos.primary.TrecAccountRepo;
import com.trecapps.auth.webflux.repos.secondary.BrandEntryRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;

import java.time.OffsetDateTime;
import java.util.*;

@Service
@ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
public class BrandServiceAsync {

    @Autowired
    IUserStorageServiceAsync userStorageService;

    @Autowired
    BrandEntryRepo brandEntryRepo;

    @Autowired
    JwtTokenServiceAsync jwtTokenService;

    @Autowired
    SessionManagerAsync sessionManager;

    @Autowired
    TrecAccountRepo trecAccountRepo;

    private static final Integer MAX_BRAND_COUNT = 6;

    public Mono<String> createNewBrand(TrecAccount account, String name)
    {
        return userStorageService.getAccountById(account.getId())
                .flatMap((Optional<TcUser> oUsers) -> {
                    if(oUsers.isPresent()){
                        TcUser user = oUsers.get();

                        Set<String> brands = user.getBrands();

                        if(brands == null)
                            brands = new TreeSet<>();

                        Set<String> captured = brands;

                        if(brands.size() >= MAX_BRAND_COUNT)
                            return Mono.just("409: User Already has too many Brand-Accounts");

                        BrandEntry newEntry = new BrandEntry();
                        newEntry.setCreator(account.getId());
                        newEntry.setName(name);

                        return brandEntryRepo.save(newEntry)
                                .map((BrandEntry savedEntry) -> {
                                    TcBrands newBrand = new TcBrands();
                                    newBrand.setId(savedEntry.getId());
                                    newBrand.setName(name);
                                    Set<String> owners = new TreeSet<>();
                                    owners.add(account.getId());
                                    newBrand.setOwners(owners);

                                    captured.add(savedEntry.getId());
                                    user.setBrands(captured);

                                    userStorageService.saveBrand(newBrand);
                                    userStorageService.saveUser(user);
                                    return "200: Success";
                                });
                    }
                    return Mono.just("500: Could not get User Information from Storage");
                });
    }

    public Mono<Boolean> isOwner(TrecAccount account, String brand)
    {
        return userStorageService.getBrandById(brand)
                .map((Optional<TcBrands> oBrand) -> {
                    if(oBrand.isEmpty())
                        return false;
                    TcBrands theBrand = oBrand.get();
                    return theBrand.getOwners().contains(account.getId());
                });
    }

    public Mono<List<BrandEntry>> getBrandList(TrecAccount account)
    {
        return userStorageService.getAccountById(account.getId())
                .flatMap((Optional<TcUser> oUser) -> {
                    if(oUser.isPresent())
                    {
                        TcUser user = oUser.get();
                        List<BrandEntry> ret = new ArrayList<>();

                        var brands = user.getBrands();
                        if(brands == null)
                            return Mono.just(ret);
                        return Flux.just(brands.toArray(new String[]{}))
                                .flatMap((String brandId) -> brandEntryRepo.findById(brandId))
                                .doOnNext(ret::add)
                                .collectList();
                    }
                    return Mono.just(new ArrayList<>());
                });
    }

    public Mono<Optional<TcBrands>> getBrandById(String brandId, TrecAccount account)
    {
        return userStorageService.getBrandById(brandId)
                .flatMap((Optional<TcBrands> oBrands) -> {
                    if(oBrands.isPresent()){
                        TcBrands brand = oBrands.get();
                        return isOwner(account, brandId).doOnNext((Boolean isOwner) -> brand.setOwners(null))
                                .map((Boolean b) -> oBrands);
                    }
                    return Mono.just(oBrands);
                });
    }

    public Mono<Optional<LoginToken>> LoginAsBrand(TrecAuthentication account, String brandId, String userAgent, String session, boolean doesExpire, String app)
    {
        return isOwner(account.getAccount(), brandId)
                .flatMap((Boolean isOwner) -> {
                   if(!isOwner) return Mono.just(Optional.empty());

                   return userStorageService.getBrandById(brandId)
                           .map((Optional<TcBrands> oBrands) -> {
                               TcBrands brand = oBrands.orElse(null);
                               TokenTime time = jwtTokenService.generateToken(account.getAccount(), userAgent, brand, session, doesExpire, app);

                               sessionManager.setBrand(account.getAccount().getId(), session, brandId);

                               LoginToken ret = new LoginToken();
                               ret.setAccess_token(time.getToken());
                               OffsetDateTime exp = time.getExpiration();
                               if(exp != null)
                                   ret.setExpires_in(exp.getNano() - OffsetDateTime.now().getNano());

                               return Optional.of(ret);
                           });
                });
    }

    public Mono<Boolean> assignOwner(TrecAccount currentOwner, String newId, String brandId)
    {
        return brandEntryRepo.existsById(brandId)
                .flatMap((Boolean brandExists) -> {
                    return !brandExists ? Mono.just(false) : trecAccountRepo.existsById(newId);
                }).flatMap((Boolean brandAndUserExists) -> {
                    return !brandAndUserExists ? Mono.just(false) : isOwner(currentOwner, brandId);
                }).flatMap((Boolean isOwner) -> {
                    if(!isOwner) return Mono.just(false);

                    return userStorageService.getAccountById(newId)
                            .flatMap((Optional<TcUser> oUser) -> {
                                if(oUser.isEmpty()) return Mono.just(false);
                                TcUser newUser = oUser.get();
                                Set<String> brands = newUser.getBrands();
                                if(brands == null)
                                    brands = new TreeSet<>();
                                if(brands.size() >= MAX_BRAND_COUNT)
                                    return Mono.just(false);

                                Set<String> cBrands = brands;

                                return userStorageService.getBrandById(brandId)
                                        .map((Optional<TcBrands> oBrands) -> {
                                            if(oBrands.isEmpty())return false;
                                            TcBrands brand = oBrands.get();
                                            cBrands.add(brandId);
                                            brand.getOwners().add(newId);
                                            newUser.setBrands(cBrands);

                                            userStorageService.saveBrand(brand);
                                            userStorageService.saveUser(newUser);
                                            return true;
                                        });
                            });
                });
    }
}
