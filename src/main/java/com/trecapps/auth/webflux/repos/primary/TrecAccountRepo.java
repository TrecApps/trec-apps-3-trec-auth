package com.trecapps.auth.webflux.repos.primary;

import com.trecapps.auth.common.models.primary.TrecAccount;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
@Repository
public interface TrecAccountRepo extends ReactiveCrudRepository<TrecAccount, String> {

    Mono<Boolean> existsByUsername(String username);

    Mono<TrecAccount> findByUsername(String username);
}
