package com.trecapps.auth.common.models;

import com.trecapps.auth.common.encryptors.EncryptedField;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class MfaMechanism {

    String source; // "Email", "Phone", "Google" etc.

    @EncryptedField
    String code;        // Code the user needs to type to perform MFA (for "Email" or "Phone" methods)

    OffsetDateTime expires; // Time the code above is to expire

    @EncryptedField
    String UserCode;    // Code to store when using a third party like Google or Microsoft to aid in Authentication
}
