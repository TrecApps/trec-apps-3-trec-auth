package com.trecapps.auth.models;

import lombok.Data;

@Data
public class PhoneNumber {

    private long number;
    private PhoneCountryCode countryCode = PhoneCountryCode.US;

    public String toString(){
        return String.format("+%d%d", countryCode.getCode(), number);
    }
}
