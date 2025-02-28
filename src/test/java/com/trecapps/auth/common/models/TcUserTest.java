package com.trecapps.auth.common.models;

import com.trecapps.auth.ObjectTestProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class TcUserTest {

    TcUser user = ObjectTestProvider.getTcUser();


    @Test
    void testGetMainProfilePic(){
        Map<String, String> pics = new HashMap<>();
        pics.put("Main", "mainPic.png");
        pics.put("watercooler", "waterCollerPic.png");
        user.setProfilePics(pics);

        Optional<String> oString = user.GetMainProfilePic();
        Assertions.assertTrue(oString.isPresent());
        Assertions.assertEquals("mainPic.png", oString.get());

        pics.remove("Main");
        oString = user.GetMainProfilePic();
        Assertions.assertTrue(oString.isEmpty());
    }

    @Test
    void testAuthorities(){
        user.getAuthRoles().add("EMAIL_VERIFIED");
        user.getAuthRoles().add("PHONE_VERIFIED");

        user.addAuthority("MFA");

        Collection<GrantedAuthority> grantedAuthorities = (Collection<GrantedAuthority>) user.getAuthorities();

        Assertions.assertEquals(3, grantedAuthorities.size());
    }

    @Test
    void testNewEmailSystem(){
        user.setProposedEmail("john.doe@gmail.com");
        user.verifyEmail();
        Assertions.assertEquals("john.doe@gmail.com", user.getVerifiedEmail());

        user.setProposedEmail("jane.doe@gmail.com");
        user.verifyEmail();
        Assertions.assertEquals("jane.doe@gmail.com", user.getVerifiedEmail());

        Assertions.assertTrue(user.verifyEmail("john.doe@gmail.com"));
        Assertions.assertEquals("john.doe@gmail.com", user.getVerifiedEmail());

        Assertions.assertFalse(user.verifyEmail("joker@gmail.com"));
        Assertions.assertEquals("john.doe@gmail.com", user.getVerifiedEmail());
    }

    @Test
    void testNewPhoneSystem(){
        PhoneNumber number = new PhoneNumber("5555555555");
        user.setProposedNumber(number);
        user.verifyPhone();
        Assertions.assertEquals(number, user.getVerifiedNumber());
    }
}
