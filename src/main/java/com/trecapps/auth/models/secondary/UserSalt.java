package com.trecapps.auth.models.secondary;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Table
@Entity
@Data
@AllArgsConstructor
public class UserSalt {

    @Id
    String id;
    String salt;
}
