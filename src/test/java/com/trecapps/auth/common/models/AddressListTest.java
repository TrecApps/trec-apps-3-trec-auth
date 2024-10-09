package com.trecapps.auth.common.models;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;


public class AddressListTest {

    Address address1 = new Address();
    Address address2 = new Address();

    AddressList addressList = new AddressList();

    @BeforeEach
    void prep(){
        address1.country = "US";
        address1.region = "CA";
        address2.country = "US";
        address2.region = "MN";

        addressList.getAddressList().add(address1);
        addressList.getAddressList().add(address2);

    }

    @Test
    void testMailingList(){
        Assertions.assertFalse(addressList.setMailingAddress(2));
        Assertions.assertTrue(addressList.setMailingAddress(0));

        Optional<Address> mailingAddress = addressList.getMailingAddress();
        Assertions.assertTrue(mailingAddress.isPresent());

        Assertions.assertEquals(address1, mailingAddress.get());
    }

    @Test
    void testBillingList(){
        Assertions.assertFalse(addressList.setBillingAddress(2));
        Assertions.assertTrue(addressList.setBillingAddress(1));

        Optional<Address> billingAddress = addressList.getBillingAddress();
        Assertions.assertTrue(billingAddress.isPresent());

        Assertions.assertEquals(address2, billingAddress.get());
    }
}
