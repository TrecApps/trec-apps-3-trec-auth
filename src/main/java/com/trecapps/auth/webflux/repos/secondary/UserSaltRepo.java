package com.trecapps.auth.webflux.repos.secondary;

import com.trecapps.auth.common.models.secondary.UserSalt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSaltRepo extends JpaRepository<UserSalt, String> {
}
