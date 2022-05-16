package com.trecapps.auth.repos.secondary;

import com.trecapps.auth.models.secondary.UserSalt;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSaltRepo extends JpaRepository<UserSalt, String> {
}
