package com.trecapps.auth.models.secondary;

import jakarta.persistence.*;
import lombok.Data;

import org.hibernate.annotations.GenericGenerator;
import org.hibernate.id.UUIDGenerator;
import org.hibernate.id.uuid.UuidGenerator;

import java.util.UUID;

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
