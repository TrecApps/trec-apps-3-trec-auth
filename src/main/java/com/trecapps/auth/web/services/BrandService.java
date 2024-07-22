package com.trecapps.auth.web.services;

import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.models.primary.TrecAccount;
import com.trecapps.auth.common.models.secondary.BrandEntry;
import com.trecapps.auth.common.repos.primary.TrecAccountRepo;
import com.trecapps.auth.common.repos.secondary.BrandEntryRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.*;

@Service
@ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
public class BrandService {

    @Autowired
    IUserStorageService userStorageService;

    @Autowired
    BrandEntryRepo brandEntryRepo;

    @Autowired
    JwtTokenService jwtTokenService;

    @Autowired
    V2SessionManager sessionManager;

    @Autowired
    TrecAccountRepo trecAccountRepo;

    private static final Integer MAX_BRAND_COUNT = 6;

    public String createNewBrand(TrecAccount account, String name)
    {
        Optional<TcUser> oUser = userStorageService.getAccountById(account.getId());
        if(oUser.isEmpty()) return "500: Could not get User Information from Storage";

        TcUser user = oUser.get();

        Set<String> brands = user.getBrands();

        if(brands == null)
            brands = new TreeSet<>();

        if(brands.size() >= MAX_BRAND_COUNT)
            return "409: User Already has too many Brand-Accounts";

        BrandEntry newEntry = new BrandEntry();
        newEntry.setCreator(account.getId());
        newEntry.setName(name);
        newEntry = brandEntryRepo.save(newEntry);

        TcBrands newBrand = new TcBrands();
        newBrand.setId(newEntry.getId());
        newBrand.setName(name);
        Set<String> owners = new TreeSet<>();
        owners.add(account.getId());
        newBrand.setOwners(owners);

        brands.add(newEntry.getId());
        user.setBrands(brands);

        userStorageService.saveBrand(newBrand);
        userStorageService.saveUser(user);
        return "200: Success";

    }

    public boolean isOwner(TrecAccount account, String brand)
    {
        Optional<TcBrands> oBrands = userStorageService.getBrandById(brand);
        return oBrands.map(tcBrands -> tcBrands.getOwners().contains(account.getId())).orElse(false);
    }

    public List<BrandEntry> getBrandList(TrecAccount account)
    {
        Optional<TcUser> oUser = userStorageService.getAccountById(account.getId());

        if(oUser.isEmpty()) return null;

        TcUser user = oUser.get();
        List<BrandEntry> ret = new ArrayList<>();

        var brands = user.getBrands();
        if(brands == null)
            return ret;
        for(String brandId : brands)
        {
            Optional<BrandEntry> entry = brandEntryRepo.findById(brandId);
            entry.ifPresent(ret::add);
        }
        return ret;

    }

    public TcBrands getBrandById(String brandId, TrecAccount account)
    {
        Optional<TcBrands> oBrands = userStorageService.getBrandById(brandId);
        if(oBrands.isEmpty()) return null;
        TcBrands brand = oBrands.get();
        if(!isOwner(account, brandId))
        {
            brand.setOwners(new HashSet<>());
        }
        return brand;
    }

    public LoginToken loginAsBrand(TrecAuthentication account, String brandId, String userAgent, String session, boolean doesExpire, String app)
    {
        if(!isOwner(account.getAccount(), brandId))
            return null;
        Optional<TcBrands> oBrand = userStorageService.getBrandById(brandId);
        TcBrands brand = oBrand.orElse(null);
        TokenTime time = jwtTokenService.generateToken(account.getAccount(), userAgent, brand, session, doesExpire, app);

        sessionManager.setBrand(account.getAccount().getId(), session, brandId, app);

        LoginToken ret = new LoginToken();
        ret.setAccess_token(time.getToken());
        OffsetDateTime exp = time.getExpiration();
        if(exp != null)
            ret.setExpires_in(exp.getNano() - OffsetDateTime.now().getNano());

        return ret;

    }

    public boolean assignOwner(TrecAccount currentOwner, String newId, String brandId)
    {
        if(!brandEntryRepo.existsById(brandId) || !trecAccountRepo.existsById(newId))
            return false;
        if(!isOwner(currentOwner, brandId))
            return false;

        Optional<TcUser> oUser = userStorageService.getAccountById(newId);
        if(oUser.isEmpty())return false;
        TcUser newUser = oUser.get();

        Set<String> brands = newUser.getBrands();
        if(brands == null)
            brands = new TreeSet<>();
        if(brands.size() >= MAX_BRAND_COUNT)
            return false;
        Optional<TcBrands> oBrand = userStorageService.getBrandById(brandId);
        if(oBrand.isEmpty())return false;
        TcBrands brand = oBrand.get();
        brands.add(brandId);
        brand.getOwners().add(newId);
        newUser.setBrands(brands);

        userStorageService.saveBrand(brand);
        userStorageService.saveUser(newUser);
        return true;

    }
}
