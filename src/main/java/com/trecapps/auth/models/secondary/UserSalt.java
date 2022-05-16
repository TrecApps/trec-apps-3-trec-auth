package com.trecapps.auth.models.secondary;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Table
@Entity
@Data
public class UserSalt {

    @Id
    String id;
    String salt;
}
