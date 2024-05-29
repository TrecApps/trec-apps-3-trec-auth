package com.trecapps.auth.webflux.repos.secondary;

import com.trecapps.auth.common.models.secondary.BrandEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BrandEntryRepo extends JpaRepository<BrandEntry, String> {
}
