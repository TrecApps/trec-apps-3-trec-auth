package com.trecapps.auth.repos.secondary;

import com.trecapps.auth.models.secondary.BrandEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BrandEntryRepo extends JpaRepository<BrandEntry, String> {
}
