package com.trecapps.auth.common.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class TokenTime {
    String token, session;

    @JsonProperty("expiration")
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm")
    OffsetDateTime expiration;

    boolean oldToken = false;

    transient boolean valid = true;
    public static TokenTime getInvalidInstance(){
        TokenTime ret = new TokenTime();
        ret.valid = false;
        return ret;
    }
}
