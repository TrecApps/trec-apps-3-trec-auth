package com.trecapps.auth.web.repos.secondary;

import com.trecapps.auth.common.models.secondary.UserSalt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSaltRepo extends JpaRepository<UserSalt, String> {
}
