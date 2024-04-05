package com.trecapps.auth.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.trecapps.auth.encryptors.EncryptedField;
import lombok.Data;

@Data
public class PhoneNumber {

    @EncryptedField
    private String number;
    private PhoneCountryCode countryCode = PhoneCountryCode.US;

    @JsonCreator
    public PhoneNumber(long number){
        setNumber(number);
    }

    @JsonCreator
    public PhoneNumber(String number){
        this.number = String.valueOf(Long.parseLong(number));
    }

    public void setNumber(long number){
        this.number = String.valueOf(number);
    }

    public String toString(){
        return String.format("+%d%s", countryCode.getCode(), number);
    }
}
