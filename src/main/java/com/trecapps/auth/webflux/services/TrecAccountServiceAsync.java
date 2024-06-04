package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.primary.TrecAccount;
import com.trecapps.auth.common.models.secondary.UserSalt;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.webflux.repos.primary.TrecAccountRepo;
import com.trecapps.auth.webflux.repos.secondary.UserSaltRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.util.Pair;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Service
@ConditionalOnProperty(prefix = "trecauth", name = "login", havingValue = "true")
public class TrecAccountServiceAsync implements ReactiveUserDetailsService {

    @Autowired
    TrecAccountRepo trecRepo;

    @Autowired
    UserSaltRepo saltRepo;

    @Autowired
    FailedLoginServiceAsync failedLoginService;

    @Autowired
    IFieldEncryptor encryptor;

    @Value("${trecauth.failed.count:10}")
    Integer loginLimit;

    final String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789"
            + "abcdefghijklmnopqrstuvxyz";
    final int RANDOM_STRING_LENGTH = 30;

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

    public Mono<Boolean> userNameExists(String username)
    {
        return Mono.just(trecRepo.existsByUsername(username));
    }

    public Mono<Optional<TrecAccount>> saveNewAccount(TrecAccount a)
    {
        return Mono.just(a)
                .map((TrecAccount account) -> {

                    if(trecRepo.existsByUsername(account.getUsername()))
                        return Optional.empty();

                    // Let the Repo Set the ID
                    account.setId(null);

                    // Never Store raw passwords in a database
                    String password = account.getPassword();
                    if(password == null) return Optional.empty();
                    account.setPasswordHash(null);
                    account = trecRepo.save(account);

                    String plainSalt = BCrypt.gensalt();
                    UserSalt userSalt = new UserSalt(account.getId(), plainSalt);

                    saltRepo.save(encryptor.encrypt(userSalt));

                    account.setPasswordHash(BCrypt.hashpw(password, plainSalt));
                    return Optional.of(trecRepo.save(account));
                });

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

        UserSalt actSalt = encryptor.decrypt(salt.get());

        if(trecAccount.getPassword().equals(BCrypt.hashpw(oldPassword, actSalt.getSalt())))
        {
            String newSalt = BCrypt.gensalt();

            trecAccount.setPasswordHash(BCrypt.hashpw(newPassword, newSalt));
            trecAccount = trecRepo.save(trecAccount);

            actSalt.setSalt(newSalt);
            actSalt = saltRepo.save(encryptor.encrypt(actSalt));

            return true;
        }
        return false;
    }

    public Mono<Optional<TrecAccount>> logInUsername(String username, String password) {

        Pair<String, String> up = Pair.of(username, password);

        return Mono.just(up)
                .flatMap((Pair<String, String> pair) -> {
                    String u = pair.getFirst();

                    if(!trecRepo.existsByUsername(u))
                        return Mono.just(TrecAccount.getInvalidAccount(true));

                    TrecAccount ret = trecRepo.findByUsername(u);
                    String id = ret.getId();

                    return failedLoginService.isLocked(id)
                            .map((Boolean locked) -> {
                                if(locked)
                                    return Mono.just(TrecAccount.getInvalidAccount(false));
                                Optional<UserSalt> saltOpt = saltRepo.findById(id);
                                if(saltOpt.isEmpty())
                                    throw new IllegalStateException(String.format("Salt for %s not found", id));
                                UserSalt salt = saltOpt.get();
                                if(ret.getPassword().equals(BCrypt.hashpw(password, encryptor.decrypt(salt).getSalt())))
                                    return Mono.just(ret);
                                return failedLoginService.appendFailedLogin(id)
                                        .map((Integer res) -> TrecAccount.getInvalidAccount(res < loginLimit));
                            }).flatMap(m -> m);
                }).map((TrecAccount tc) -> tc.makeNull() ? Optional.empty() : Optional.of(tc));

    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {

        return Mono.just(username)
                .map((String u) -> {
                   if(trecRepo.existsByUsername(u))
                       return trecRepo.findByUsername(u);
                   return null;
                });

    }
}
