package com.trecapps.auth.common.models.secondary;

import jakarta.persistence.*;
import lombok.Data;

@Table
@Entity
@javax.persistence.Entity
@Data
public class BrandEntry {

    @Id
    @javax.persistence.Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;

    String creator;

    String name;
}
