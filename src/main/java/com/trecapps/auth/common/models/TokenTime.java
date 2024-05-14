package com.trecapps.auth.common.models;

import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class TokenTime {
    String token, session;
    OffsetDateTime expiration;

    transient boolean valid = true;
    public static TokenTime getInvalidInstance(){
        TokenTime ret = new TokenTime();
        ret.valid = false;
        return ret;
    }
}
