package com.trecapps.auth.common.models;

public enum PhoneCountryCode {

    // To-Do: Add More Country Codes
    US(1);


    PhoneCountryCode(int code){
        this.code = String.valueOf(code);
    }

    String code;

    public int getCode(){return Integer.parseInt(code);};
}
