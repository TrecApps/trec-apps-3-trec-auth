package com.trecapps.auth.webflux.services;

import com.trecapps.auth.common.models.AppLocker;
import com.trecapps.auth.common.models.FailedLoginList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class FailedLoginServiceAsync {

    @Autowired
    IUserStorageServiceAsync userStorageService;

    @Value("${trecauth.failed.count:10}")
    Integer loginLimit;

    @Value("${trecauth.failed.span:30}")
    Integer loginLimitSpan;

    @Value("${trecauth.app}")
    String app;

    public Mono<Integer> appendFailedLogin(String id)
    {
        return
             userStorageService.retrieveAppLocker(id)
                     .map((Optional<AppLocker> oAppLocker) -> {
                         if(oAppLocker.isEmpty())
                             return 0;
                         AppLocker locker = oAppLocker.get();
                         Map<String, FailedLoginList> appList = locker.getLoginListMap();

                         FailedLoginList loginList = null;

                         if(appList.containsKey(app))
                             loginList = appList.get(app);
                         else
                         {
                             loginList = new FailedLoginList();
                             loginList.setFailedLogins(new ArrayList<>());
                             appList.put(app, loginList);
                         }

                         List<OffsetDateTime> failedLogins = loginList.getFailedLogins();

                         OffsetDateTime now = OffsetDateTime.now();
                         failedLogins.add(now);

                         OffsetDateTime minuteSpan = now.minusMinutes(loginLimitSpan);

                         for(int c = 0; c < failedLogins.size(); c++)
                         {
                             if(failedLogins.get(c).isBefore(minuteSpan))
                                 failedLogins.remove(c--);
                         }

                         if(failedLogins.size() >= loginLimit)
                             loginList.setUnlockTime(OffsetDateTime.now().plus(1, ChronoUnit.HOURS));
                         userStorageService.saveLogins(locker, id);
                         return failedLogins.size();
                     });
    }

    public Mono<Boolean> isLocked(String id)
    {
        return userStorageService.retrieveAppLocker(id)
                .map((Optional<AppLocker> oAppLocker) -> {
                    if(oAppLocker.isEmpty())
                        return true;
                    AppLocker locker = oAppLocker.get();
                    Map<String, FailedLoginList> appList = locker.getLoginListMap();

                    if(!appList.containsKey(app))
                        return false;

                    FailedLoginList loginList = appList.get(app);

                    OffsetDateTime lockLimit = loginList.getUnlockTime();

                    // If there is a lock limit in place, check to see if we have passed it
                    if(lockLimit != null)
                    {
                        // if we haven't passed the limit, account is still locked
                        if(lockLimit.isAfter(OffsetDateTime.now()))
                            return true;

                        // If we have passed it, clear the login list
                        loginList.setUnlockTime(null);
                        loginList.setFailedLogins(new ArrayList<>());
                        userStorageService.saveLogins(locker, id);
                    }
                    return false;

        });
    }
}
