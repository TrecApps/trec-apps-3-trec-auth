package com.trecapps.auth.repos.primary;

import com.trecapps.auth.models.primary.TrecAccount;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrecAccountRepo extends JpaRepository<TrecAccount, String> {

    boolean existsByUsername(String username);

    TrecAccount findByUsername(String username);
}
