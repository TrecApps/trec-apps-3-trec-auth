package com.trecapps.auth.common.models;

import lombok.Data;

@Data
public class TokenOptions {
    boolean useMfa = false;
    boolean needsMfa = false;
    boolean expires = false;
    String session;
}
