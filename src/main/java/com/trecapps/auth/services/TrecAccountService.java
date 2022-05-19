package com.trecapps.auth.services;

import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.models.secondary.UserSalt;
import com.trecapps.auth.repos.primary.TrecAccountRepo;
import com.trecapps.auth.repos.secondary.UserSaltRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TrecAccountService implements UserDetailsService {

    @Autowired
    TrecAccountRepo trecRepo;

    @Autowired
    UserSaltRepo saltRepo;
    final String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789"
            + "abcdefghijklmnopqrstuvxyz";
    final int RANDOM_STRING_LENGTH = 20;

    private String generateRandomString()
    {
        StringBuilder sb = new StringBuilder();
        for(int c = 0; c < RANDOM_STRING_LENGTH; c++)
        {
            int ch = (int) (Math.random() * AlphaNumericString.length());
            sb.append(AlphaNumericString.charAt(ch));
        }
        return sb.toString();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(!trecRepo.existsByUsername(username))
            return null;

        return trecRepo.findByUsername(username);
    }

    public boolean userNameExists(String username)
    {
        return trecRepo.existsByUsername(username);
    }

    public TrecAccount saveNewAccount(TrecAccount account)
    {
        // First, see if the TrecAccount already Exists.
        boolean exists = trecRepo.existsByUsername(account.getUsername());

        if(exists)
        {
            return null;
        }
        else
        {
            // Let the Repo Set the ID
            account.setId(null);
            String curPassword = account.getPasswordHash();

            // Never Store raw passwords in a database
            account.setPasswordHash(null);
            account = trecRepo.save(account);

            UserSalt userSalt = new UserSalt(account.getId(), generateRandomString());
            saltRepo.save(userSalt);

            account.setPasswordHash(BCrypt.hashpw(curPassword, userSalt.getSalt()));
            return trecRepo.save(account);

        }


    }



    public Optional<TrecAccount> getAccountById(String id)
    {
        return trecRepo.findById(id);
    }

    public boolean changePassword(TrecAccount account, String oldPassword, String newPassword)
    {
        Optional<TrecAccount> savedAccount = trecRepo.findById(account.getId());

        TrecAccount trecAccount = savedAccount.get();

        Optional<UserSalt> salt = saltRepo.findById(trecAccount.getId());

        if(salt.isEmpty())
            return false;

        UserSalt actSalt = salt.get();

        if(trecAccount.getPassword().equals(BCrypt.hashpw(oldPassword, actSalt.getSalt())))
        {
            String newSalt = generateRandomString();

            trecAccount.setPasswordHash(BCrypt.hashpw(newPassword, newSalt));
            trecAccount = trecRepo.save(trecAccount);

            actSalt.setSalt(newSalt);
            actSalt = saltRepo.save(actSalt);

            return true;
        }
        return false;
    }

    public TrecAccount logInUsername(String username, String password) {
        if(!trecRepo.existsByUsername(username))
            return null;

        TrecAccount ret = trecRepo.findByUsername(username);

        String id = ret.getId();

        Optional<UserSalt> salt = saltRepo.findById(id);

        if(salt.isEmpty())
            return null;

        UserSalt actSalt = salt.get();

        if(ret.getPassword().equals(BCrypt.hashpw(password, actSalt.getSalt())))
            return ret;

        // To-Do: Process Failed Login Attempt

        return null;
    }
}
