package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.primary.TrecAccount;
import com.trecapps.auth.common.models.secondary.UserSalt;
import com.trecapps.auth.common.encryptors.IFieldEncryptor;
import com.trecapps.auth.webflux.repos.primary.TrecAccountRepo;
import com.trecapps.auth.webflux.repos.secondary.UserSaltRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
        return trecRepo.existsByUsername(username);
    }

    public Mono<Optional<TrecAccount>> saveNewAccount(TrecAccount account)
    {
        // First, see if the TrecAccount already Exists.
        return trecRepo.existsByUsername(account.getUsername())
                .map((Boolean exists) -> {
                    if(exists) throw new IllegalStateException();


                    // Let the Repo Set the ID
                    account.setId(null);

                    // Never Store raw passwords in a database
                    account.setPasswordHash(null);
                    return trecRepo.save(account)
                            .flatMap((TrecAccount tc) -> {
                                String plainSalt = BCrypt.gensalt();
                                UserSalt userSalt = new UserSalt(tc.getId(), plainSalt);

                                return saltRepo.save(encryptor.encrypt(userSalt))
                                        .map((UserSalt us) -> {
                                            tc.setPasswordHash(BCrypt.hashpw(account.getPassword(), plainSalt));
                                            return trecRepo.save(tc);
                                        });
                                }).flatMap(tc-> tc)
                            .map(Optional::of);
                }).flatMap(tc -> tc)
                .onErrorReturn(IllegalStateException.class, Optional.empty());



    }



    public Mono<TrecAccount> getAccountById(String id)
    {
        return trecRepo.findById(id);
    }

    public Mono<Boolean> changePassword(TrecAccount account, String oldPassword, String newPassword)
    {
        return trecRepo.findById(account.getId())
                .flatMap((TrecAccount trecAccount) -> {
                    return saltRepo.findById(account.getId())
                            .flatMap((UserSalt userSalt) -> {
                                UserSalt actSalt = encryptor.decrypt(userSalt);
                                if(trecAccount.getPassword().equals(BCrypt.hashpw(oldPassword, actSalt.getSalt()))) {

                                    String newSalt = BCrypt.gensalt();

                                    trecAccount.setPasswordHash(BCrypt.hashpw(newPassword, newSalt));
                                    return trecRepo.save(trecAccount)
                                            .map((TrecAccount tc) -> {
                                                actSalt.setSalt(newSalt);
                                                return saltRepo.save(encryptor.encrypt(actSalt));
                                            }).flatMap(us -> Mono.just(true));
                                }
                                return Mono.just(false);
                            });
                });
    }

    public Mono<Optional<TrecAccount>> logInUsername(String username, String password) {

        return trecRepo.existsByUsername(username)
                .map((Boolean exists) -> {
                   if(!exists) return Mono.just(TrecAccount.getInvalidAccount(true));

                   return trecRepo.findByUsername(username)
                           .map((TrecAccount ret) -> {
                               String id = ret.getId();

                               return failedLoginService.isLocked(id)
                                       .map((Boolean locked) -> {
                                           if(locked)
                                               return Mono.just(TrecAccount.getInvalidAccount(false));
                                           return saltRepo.findById(id)
                                                   .map((UserSalt salt) -> {
                                                       if(ret.getPassword().equals(BCrypt.hashpw(password, encryptor.decrypt(salt).getSalt())))
                                                           return Mono.just(ret);
                                                       return failedLoginService.appendFailedLogin(id)
                                                               .map((Integer res) -> TrecAccount.getInvalidAccount(res < loginLimit));
                                                   }).flatMap(m -> m);
                                       }).flatMap(m->m);

                           }).flatMap(m->m);
                }).flatMap((Mono<TrecAccount> mono) -> mono.map((TrecAccount tc) -> tc.makeNull() ? Optional.empty() : Optional.of(tc)));


    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return this.trecRepo.findByUsername(username).map((TrecAccount tc) -> (UserDetails) tc);
    }
}
