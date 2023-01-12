package com.trecapps.auth.models.secondary;

import lombok.Data;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;

@Table
@Entity
@javax.persistence.Entity
@Data
public class BrandEntry {

    @Id
    @javax.persistence.Id
    UUID id;

    String creator;

    String name;
}
