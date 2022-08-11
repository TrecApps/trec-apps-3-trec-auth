package com.trecapps.auth.models;

import lombok.Data;

import javax.validation.constraints.Email;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Data
public class TcUser {


    // Core Info
    String id;
    String profilePic;
    String displayName;
    String userProfile;

    // Phone Used by the User
    String mobilePhone;
    boolean phoneVerified;

    // External Email used by the User
    @Email
    String email;
    boolean emailVerified;

    // Aides in phone/Email Verification
    String currentCode;
    OffsetDateTime codeExpiration;

    // Birthday
    OffsetDateTime birthday;
    String birthdaySetting;

    // Addresses used by the User
    String[] address;

    // List of authorized roles
    String[] authRoles;

    // External Profiles
    Set<UUID> brands;
    Map<UUID, UUID> brandSettings; // Device/App setting determining which Brand the User is currently id-ing as

    String restrictions; // Semicolon restricted details on the claims against this user

    // Credibility rating (used by services like Falsehoods to assess how credible this user is)
    long credibilityRating;
}
