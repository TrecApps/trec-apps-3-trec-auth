package com.trecapps.auth.common.models.secondary;

import com.trecapps.auth.common.encryptors.EncryptedField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Table
@Entity
@javax.persistence.Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserSalt {

    @Id
    @javax.persistence.Id
    String id;

    @EncryptedField
    String salt;
}
