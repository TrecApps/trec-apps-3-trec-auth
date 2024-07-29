package com.trecapps.auth.common.models;

import lombok.Data;

@Data
public class MfaReq {
    String app;
    boolean requireMfa = false;
}
