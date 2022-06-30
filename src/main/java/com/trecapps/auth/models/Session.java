package com.trecapps.auth.models;

import lombok.*;

import javax.validation.constraints.NotNull;
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

    OffsetDateTime expiration;


}
