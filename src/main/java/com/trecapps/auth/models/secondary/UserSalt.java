package com.trecapps.auth.models.secondary;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Table
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserSalt {

    @Id
    String id;
    String salt;
}
