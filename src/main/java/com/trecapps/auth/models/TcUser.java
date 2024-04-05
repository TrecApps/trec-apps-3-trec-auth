package com.trecapps.auth.models;

import com.trecapps.auth.encryptors.EncryptedField;
import lombok.Data;

import jakarta.validation.constraints.Email;
import java.time.OffsetDateTime;
import java.util.*;

@Data
public class TcUser {


    // Core Info

    Integer partition; // Used for applying a Profile to the TcUser id on Azure Cosmos DB - Gremlin Service
    String id;
    String profilePic;
    String displayName;
    String userProfile;

    // Phone Used by the User
    @EncryptedField
    PhoneNumber mobilePhone;
    boolean phoneVerified;

    // External Email used by the User
    @Email
    @EncryptedField
    String email;
    boolean emailVerified;

    // Aides in phone/Email Verification
    String currentCode;
    Map<String, String> verificationCodes;
    OffsetDateTime codeExpiration;

    // Birthday
    OffsetDateTime birthday;
    String birthdaySetting;

    // Addresses used by the User
    List<String> address;

    // List of authorized roles
    List<String> authRoles;

    // External Profiles
    Set<String> brands;
    Map<UUID, UUID> brandSettings; // Device/App setting determining which Brand the User is currently id-ing as

    String restrictions; // Semicolon restricted details on the claims against this user

    // Credibility rating (used by services like Falsehoods to assess how credible this user is)
    long credibilityRating;

    Map<String, String> profilePics = new HashMap<>();

    public Optional<String> GetMainProfilePic(){
        if(profilePics.containsKey("Main"))
            return Optional.of(profilePics.get("Main"));
        return Optional.empty();
    }
}
