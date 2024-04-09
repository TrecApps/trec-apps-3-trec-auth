package com.trecapps.auth;

import com.trecapps.auth.encryptors.EncryptedField;
import lombok.Data;

@Data
public class EncryptableTestObj {

    String basicField;

    @EncryptedField
    String encryptedField;

    @EncryptedField
    EncryptableTestObj childObject;
}
