package com.trecapps.auth.common.models;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TokenTimeTest {

    @Test
    void testTokenTime(){
        TokenTime token = TokenTime.getInvalidInstance();
        Assertions.assertFalse(token.isValid());
    }
}
