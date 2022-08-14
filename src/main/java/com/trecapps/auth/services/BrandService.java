package com.trecapps.auth.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.LoginToken;
import com.trecapps.auth.models.TcBrands;
import com.trecapps.auth.models.TcUser;
import com.trecapps.auth.models.TokenTime;
import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.models.secondary.BrandEntry;
import com.trecapps.auth.repos.primary.TrecAccountRepo;
import com.trecapps.auth.repos.secondary.BrandEntryRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.*;

@Service
public class BrandService {

    @Autowired
    UserStorageService userStorageService;

    @Autowired
    BrandEntryRepo brandEntryRepo;

    @Autowired
    JwtTokenService jwtTokenService;

    @Autowired
    TrecAccountRepo trecAccountRepo;

    private static final Integer MAX_BRAND_COUNT = 6;

    public String createNewBrand(TrecAccount account, String name)
    {
        try {
            TcUser user = userStorageService.retrieveUser(account.getId());

            Set<UUID> brands = user.getBrands();

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

    public boolean isOwner(TrecAccount account, UUID brand)
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
            for(UUID brandId : user.getBrands())
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

    public TcBrands getBrandById(UUID brandId, TrecAccount account)
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

    public LoginToken LoginAsBrand(TrecAccount account, UUID brandId, String userAgent, String session, boolean doesExpire)
    {
        if(!isOwner(account, brandId))
            return null;
        try {
            TcBrands brand = userStorageService.retrieveBrand(brandId);
            TokenTime time = jwtTokenService.generateToken(account, userAgent, brand, session, doesExpire);
            String refreshToken = jwtTokenService.generateRefreshToken(account, brandId.toString(), session);

            LoginToken ret = new LoginToken();
            ret.setAccess_token(time.getToken());
            ret.setRefresh_token(refreshToken);
            OffsetDateTime exp = time.getExpiration();
            if(exp != null)
                ret.setExpires_in(exp.getNano() - OffsetDateTime.now().getNano());

            return ret;
        }catch(JsonProcessingException e)
        {
            return null;
        }

    }

    public boolean assignOwner(TrecAccount currentOwner, String newId, UUID brandId)
    {
        if(!brandEntryRepo.existsById(brandId) || !trecAccountRepo.existsById(newId))
            return false;
        if(!isOwner(currentOwner, brandId))
            return false;
        try {
            TcUser newUser = userStorageService.retrieveUser(newId);

            Set<UUID> brands = newUser.getBrands();
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