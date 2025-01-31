package com.trecapps.auth.common.models;

import com.trecapps.auth.common.encryptors.EncryptedField;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class MfaMechanism {

    String source; // "Email", "Phone", "Google" etc.

    String name; // Used for multiple Authenticator apps

    @EncryptedField
    String code;        // Code the user needs to type to perform MFA (for "Email" or "Phone" methods)

    OffsetDateTime expires; // Time the code above is to expire

    @EncryptedField
    String UserCode;    // Code to store when using a third party like Google or Microsoft to aid in Authentication

    public MfaMechanism cloneWithName(String name) {
        MfaMechanism ret = new MfaMechanism();
        ret.source = source;
        ret.code = code;
        ret.expires = expires;
        ret.UserCode = UserCode;
        ret.name = name;
        return ret;
    }

    public boolean hasName() {
        return name != null && !name.trim().isEmpty();
    }
}
