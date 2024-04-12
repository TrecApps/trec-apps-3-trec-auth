package com.trecapps.auth.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.trecapps.auth.encryptors.EncryptedField;
import com.trecapps.auth.encryptors.IFieldEncryptor;
import lombok.Data;

@Data
public class PhoneNumber {

    @EncryptedField
    private String number;
    private PhoneCountryCode countryCode = PhoneCountryCode.US;

    @JsonCreator
    public PhoneNumber(@JsonProperty("number") String number){
        // If field is currently encrypted, then unrealistic to expect pure numbers to be included
        if(number.startsWith(IFieldEncryptor.FRONT_WRAP) && number.endsWith(IFieldEncryptor.BACK_WRAP))
            this.number = number;
        else
            // It is not encrypted, thus reasonable to expect String to be parsable as a long
            this.number = String.valueOf(Long.parseLong(number));
    }

    public PhoneNumber(long number){
        setNumber(number);
    }

    public void setNumber(long number){
        this.number = String.valueOf(number);
    }

    public String toString(){
        return String.format("+%d%s", countryCode.getCode(), number);
    }
}
