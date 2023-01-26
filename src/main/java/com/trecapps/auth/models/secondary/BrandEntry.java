package com.trecapps.auth.models.secondary;

import jakarta.persistence.GeneratedValue;
import lombok.Data;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.GenericGenerator;

import java.util.UUID;

@Table
@Entity
@javax.persistence.Entity
@Data
public class BrandEntry {

    @Id
    @javax.persistence.Id
    @GeneratedValue(generator="system-uuid")
    @GenericGenerator(name="system-uuid", strategy = "uuid")
    String id;

    String creator;

    String name;
}
