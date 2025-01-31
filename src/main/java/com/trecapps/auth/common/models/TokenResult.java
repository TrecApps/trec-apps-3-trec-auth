package com.trecapps.auth.common.models;

import java.util.Objects;

public record TokenResult(String tokenCode, String name) {
    public TokenResult {
        Objects.requireNonNull(tokenCode);
        Objects.requireNonNull(name);
    }
}