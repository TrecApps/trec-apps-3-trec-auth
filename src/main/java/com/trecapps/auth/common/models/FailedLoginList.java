package com.trecapps.auth.common.models;

import lombok.Data;

import java.time.OffsetDateTime;
import java.util.List;

@Data
public class FailedLoginList {

    List<OffsetDateTime> failedLogins;
    OffsetDateTime unlockTime;
}
