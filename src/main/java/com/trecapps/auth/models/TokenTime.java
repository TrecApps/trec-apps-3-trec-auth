package com.trecapps.auth.models;

import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class TokenTime {
    String token, session;
    OffsetDateTime expiration;
}
