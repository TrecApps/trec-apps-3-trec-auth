package com.trecapps.auth;

import com.trecapps.auth.models.PhoneNumber;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class PhoneTest {

    @Test
    void testToString()
    {
        PhoneNumber phoneNumber = new PhoneNumber();

        phoneNumber.setNumber(555_555_1234L);

        Assertions.assertEquals("+15555551234", phoneNumber.toString());
    }
}
