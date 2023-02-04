package com.trecapps.auth.models;

public enum PhoneCountryCode {

    // To-Do: Add More Country Codes
    US(1);


    PhoneCountryCode(int code){
        this.code = code;
    }

    int code;

    public int getCode(){return code;};
}
