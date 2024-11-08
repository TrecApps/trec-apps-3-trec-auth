package com.trecapps.auth.common.models;

import com.trecapps.auth.common.encryptors.EncryptedField;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Data
public class AddressList {
    @EncryptedField
    List<Address> addressList = new ArrayList<>();
    int billingAddress = -1;
    int mailingAddress = -1;


    public boolean setMailingAddress(int index) {
        if(index < -1 || index >= addressList.size()) return false;
        this.mailingAddress = index;
        return true;
    }
    public boolean setBillingAddress(int index) {
        if(index < -1 || index >= addressList.size()) return false;
        this.billingAddress = index;
        return true;
    }

    public Optional<Address> getCurrentMailingAddress(){
        if(mailingAddress < 0) return Optional.empty();
        return Optional.of(addressList.get(mailingAddress));
    }
    public Optional<Address> getCurrentBillingAddress(){
        if(billingAddress < 0) return Optional.empty();
        return Optional.of(addressList.get(billingAddress));
    }
}
