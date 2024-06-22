package com.trecapps.auth.common.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.trecapps.auth.common.encryptors.EncryptedField;
import com.trecapps.auth.common.models.primary.TrecAccount;
import jakarta.persistence.Transient;
import lombok.Data;

import jakarta.validation.constraints.Email;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.OffsetDateTime;
import java.util.*;

@Data
public class TcUser implements UserDetails {


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
    @JsonProperty("birthday")
    @JsonFormat(pattern="yyyy-MM-dd")
    OffsetDateTime birthday;
    String birthdaySetting;

    // Addresses used by the User
    List<String> address;

    // List of authorized roles
    List<String> authRoles = new ArrayList<>();

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

    ///
    /// UserDetails Support
    ///

    public TrecAccount getTrecAccount()
    {
        TrecAccount ret = new TrecAccount();
        ret.setUsername(userProfile);
        ret.setId(id);
        setAuthorities();
        ret.setAuthorities(authorities);
        return ret;
    }

    @Transient
    List<String> authorities;

    private void setAuthorities() {
        if(authorities == null)
            authorities = new ArrayList<>(this.authRoles);
    }

    public void addAuthority(String auth)
    {
        setAuthorities();
        authorities.add(auth);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        setAuthorities();
        return authorities.stream()
                .map((String authStr) -> {
                    return new GrantedAuthority() {
                        @Override
                        public String getAuthority() {return authStr; }
                    };
                }).toList();
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return this.userProfile;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
