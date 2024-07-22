package com.trecapps.auth.common.repos.primary;

import com.trecapps.auth.common.models.primary.TrecAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TrecAccountRepo extends JpaRepository<TrecAccount, String> {

    boolean existsByUsername(String username);

    TrecAccount findByUsername(String username);
}
