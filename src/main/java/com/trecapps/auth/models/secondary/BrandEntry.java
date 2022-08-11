package com.trecapps.auth.models.secondary;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.UUID;

@Table
@Entity
@Data
public class BrandEntry {

    @Id
    UUID id;

    String creator;

    String name;
}
