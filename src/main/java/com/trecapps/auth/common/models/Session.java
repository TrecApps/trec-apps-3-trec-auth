package com.trecapps.auth.common.models;

import lombok.*;

import jakarta.validation.constraints.NotNull;
import java.time.OffsetDateTime;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Session {
    @NotNull
    String sessionId;
    @NotNull
    String appId;

    String deviceInfo;

    String brandId;

    OffsetDateTime expiration;


}
