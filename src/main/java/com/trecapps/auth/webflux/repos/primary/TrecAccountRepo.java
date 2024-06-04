package com.trecapps.auth.webflux.repos.primary;

import com.trecapps.auth.common.models.primary.TrecAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
@Repository
public interface TrecAccountRepo extends JpaRepository<TrecAccount, String> {

    boolean existsByUsername(String username);

    TrecAccount findByUsername(String username);


}
