package com.trecapps.auth.common.models;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.List;

public class SessionV2Test {

    @Test
    void testSessionV2() {
        SessionV2 sessionV2 = new SessionV2();
        sessionV2.setApp("app", "brandId");
        sessionV2.setDeviceId("aaaaaa");

        SessionApp app = sessionV2.getApp("app");
        Assertions.assertEquals("brandId", app.getBrandId());
        app = sessionV2.getApp("Coffeeshop");
        Assertions.assertNull(app);

        String brandString = sessionV2.getBrandByApp("app");
        Assertions.assertEquals("brandId", brandString);
        brandString = sessionV2.getBrandByApp("Coffeeshop");
        Assertions.assertNull(brandString);

        Assertions.assertFalse(sessionV2.isExpired());
        sessionV2.prep();
        Assertions.assertNull(sessionV2.getExpirationStr());

        sessionV2.setExpiration(OffsetDateTime.now().plusMinutes(2));
        Assertions.assertFalse(sessionV2.isExpired());


        sessionV2.setExpiration(OffsetDateTime.now().minusSeconds(100));

        Assertions.assertTrue(sessionV2.isExpired());

        SessionListV2 sessionListV2 = new SessionListV2();
        sessionListV2.getSessions().add(sessionV2);

        List<String> sessionIds = sessionListV2.getSessionIdList();
        Assertions.assertFalse(sessionIds.isEmpty());
        Assertions.assertEquals("aaaaaa", sessionIds.get(0));

        sessionListV2.prep();
        Assertions.assertNotNull(sessionV2.getExpirationStr());
    }

    @Test
    void testPhoneStringConstruction() {
        PhoneNumber phoneNumber = new PhoneNumber(("_ENC_(number)"));
        Assertions.assertEquals("_ENC_(number)", phoneNumber.getNumber());

        phoneNumber = new PhoneNumber("555555555");
        Assertions.assertEquals("555555555", phoneNumber.getNumber());
    }
}
