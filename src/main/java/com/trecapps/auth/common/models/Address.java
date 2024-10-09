package com.trecapps.auth.common.models;

import com.trecapps.auth.common.encryptors.EncryptedField;
import lombok.Data;

@Data
public class Address {

    String country;
    String region;
    @EncryptedField
    String address1;
    @EncryptedField
    String address2;
    String postCode;
    @EncryptedField
    String payId;

}
