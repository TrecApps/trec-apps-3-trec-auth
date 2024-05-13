package com.trecapps.auth.services.login;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.*;
import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.models.secondary.BrandEntry;
import com.trecapps.auth.repos.primary.TrecAccountRepo;
import com.trecapps.auth.repos.secondary.BrandEntryRepo;
import com.trecapps.auth.services.web.JwtTokenService;
import com.trecapps.auth.services.web.SessionManager;
import com.trecapps.auth.services.web.IUserStorageService;
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
    SessionManager sessionManager;

    @Autowired
    TrecAccountRepo trecAccountRepo;

    private static final Integer MAX_BRAND_COUNT = 6;

    public String createNewBrand(TrecAccount account, String name)
    {
        try {
            TcUser user = userStorageService.retrieveUser(account.getId());

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
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return "500: Could not get User Information from Storage";
        }
    }

    public boolean isOwner(TrecAccount account, String brand)
    {
        try {
            TcBrands theBrand = userStorageService.retrieveBrand(brand);

            return theBrand.getOwners().contains(account.getId());
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return false;
        }

    }

    public List<BrandEntry> getBrandList(TrecAccount account)
    {
        try {
            TcUser user = userStorageService.retrieveUser(account.getId());

            List<BrandEntry> ret = new ArrayList<>();

            var brands = user.getBrands();
            if(brands == null)
                return ret;
            for(String brandId : brands)
            {
                BrandEntry entry = brandEntryRepo.getById(brandId);
                ret.add(entry);
            }
            return ret;
        } catch (JsonProcessingException e)
        {
            return null;
        }
    }

    public TcBrands getBrandById(String brandId, TrecAccount account)
    {
        if(!brandEntryRepo.existsById(brandId))
            return null;
        try {
            TcBrands brand = userStorageService.retrieveBrand(brandId);
            if(!isOwner(account, brandId))
            {
                brand.setOwners(null);
            }
            return brand;
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return null;

    }

    public LoginToken LoginAsBrand(TrecAuthentication account, String brandId, String userAgent, String session, boolean doesExpire, String app)
    {
        if(!isOwner(account.getAccount(), brandId))
            return null;
        try {
            TcBrands brand = userStorageService.retrieveBrand(brandId);
            TokenTime time = jwtTokenService.generateToken(account.getAccount(), userAgent, brand, session, doesExpire, app);

            sessionManager.setBrand(account.getAccount().getId(), session, brandId);

            LoginToken ret = new LoginToken();
            ret.setAccess_token(time.getToken());
            OffsetDateTime exp = time.getExpiration();
            if(exp != null)
                ret.setExpires_in(exp.getNano() - OffsetDateTime.now().getNano());

            return ret;
        }catch(JsonProcessingException e)
        {
            return null;
        }

    }

    public boolean assignOwner(TrecAccount currentOwner, String newId, String brandId)
    {
        if(!brandEntryRepo.existsById(brandId) || !trecAccountRepo.existsById(newId))
            return false;
        if(!isOwner(currentOwner, brandId))
            return false;
        try {
            TcUser newUser = userStorageService.retrieveUser(newId);

            Set<String> brands = newUser.getBrands();
            if(brands == null)
                brands = new TreeSet<>();
            if(brands.size() >= MAX_BRAND_COUNT)
                return false;
            TcBrands brand = userStorageService.retrieveBrand(brandId);
            brands.add(brandId);
            brand.getOwners().add(newId);
            newUser.setBrands(brands);

            userStorageService.saveBrand(brand);
            userStorageService.saveUser(newUser);
            return true;
        } catch(JsonProcessingException e)
        {
            return false;
        }
    }
}
