package com.trecapps.auth.common.models;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class MfaRegistrationData {

    String qrCode;
    String userCode;

    public boolean isValid(){
        return qrCode != null && !qrCode.isEmpty() &&
                userCode != null && !userCode.isEmpty();
    }
}
