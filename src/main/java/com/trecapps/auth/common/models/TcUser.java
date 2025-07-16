package com.trecapps.auth.common.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
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

    // Phone Used by the User (Deprecated)
    @EncryptedField
    PhoneNumber mobilePhone;
    boolean phoneVerified;
    // Phone Used by the User (New Version)

    @EncryptedField
    PhoneNumber proposedNumber;
    @EncryptedField
    PhoneNumber verifiedNumber;

    // External Email used by the User (Deprecated)
    @Email
    @EncryptedField
    String email;
    boolean emailVerified;

    // External Email used by the User (New Version)
    @Email
    @EncryptedField
    String proposedEmail;
    @Email
    @EncryptedField
    String verifiedEmail;
    @EncryptedField
    Set<String> pastEmails = new HashSet<>();

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
    Set<String> brands = new HashSet<>();
    Map<UUID, UUID> brandSettings; // Device/App setting determining which Brand the User is currently id-ing as

    String restrictions; // Semicolon restricted details on the claims against this user

    // Credibility rating (used by services like Falsehoods to assess how credible this user is)
    long credibilityRating;

    Map<String, String> profilePics = new HashMap<>();

    @EncryptedField
    List<MfaMechanism> mfaMechanisms = new ArrayList<>();

    // Supports a feature called a dedicated Brand Account. Basically, people will have the option of setting
    // up a dedicated BrandAccount (meaning they alone own it). Users can also elect to automatically login to this
    // account without further action and mask their User Account (useful for public figures)
    String dedicatedBrandAccount;
    boolean autoBrandAccount;

    JsonNode extensions; // Extra Features that the library would not concern itself with


    public String callibrateMechanisms(){
        int token = 1; // Counter

        // Get a list of mechanisms that use the Token mechanism
        List<MfaMechanism> currentTokenMechs = mfaMechanisms
                .stream()
                .filter((MfaMechanism mech) -> "Token".equals(mech.getSource()))
                .toList();

        // Get a list of token mechanisms with a null name
        List<MfaMechanism> tokenMechsNull = currentTokenMechs
                .stream()
                .filter((MfaMechanism mech) -> !mech.hasName())
                .toList();

        // List of token mechanisms that follow the default name convention "tokenX" where "X" is 1,2,3...
        List<MfaMechanism> tokenMechDefault = currentTokenMechs
                .stream()
                .filter((MfaMechanism mech) -> {
                    if(!mech.hasName())
                        return false;
                    String name = mech.getName();
                    return name.startsWith(("token_")) &&
                            name.length() >= 7;
                })
                .filter((MfaMechanism mech) -> {
                    String nameNum = mech.getName().substring(6);
                    try{Integer.parseInt(nameNum); return true; }
                    catch(NumberFormatException ignore) {return false;}
                })
                .map((MfaMechanism mech) -> {
                    String nameNum = mech.getName().substring(6);
                    // We don't actually want to modify their names, just use them to name the null-named tokens.
                    // So clone them
                    return mech.cloneWithName(String.format("token_%s", nameNum.trim()));
                })
                .sorted()
                .toList();

        if(!tokenMechDefault.isEmpty())
        {
            String lastName = tokenMechDefault.get(tokenMechDefault.size() - 1).getName().substring(6);
            token = Integer.parseInt(lastName) + 1;
        }

        for(MfaMechanism mech: tokenMechsNull) {
            mech.setName(String.format("token_%d", token++));
        }

        return String.format("token_%d", token);
    }

    public boolean isMechanismNameTaken(String name) {
        if(name == null || !name.trim().isEmpty()) return false;
        for(MfaMechanism mech: mfaMechanisms){
            if(name.equals(mech.getName()))return true;
        }

        return false;
    }

    List<MfaReq> mfaRequirements = new ArrayList<>();

    @EncryptedField
    String subscriptionId;

    @EncryptedField
    String customerId;

    @EncryptedField
    AddressList addressList;


    public void verifyEmail(){
        this.verifiedEmail = this.proposedEmail;
        this.pastEmails.add(this.verifiedEmail);
    }

    public boolean verifyEmail(String email){
        if(pastEmails.contains(email)) {
            this.verifiedEmail = email;
            return true;
        }
        return false;
    }

    public void verifyPhone(){
        this.verifiedNumber = this.proposedNumber;
    }


    public Optional<MfaMechanism> getMechanism(String source, String name) {
        for(MfaMechanism mech: mfaMechanisms){
            if(source.equals(mech.getSource()) && name.equals(mech.getName()))
                return Optional.of(mech);
        }
        return Optional.empty();
    }

    public Optional<MfaMechanism> getMechanism(String source) {
        for(MfaMechanism mech: mfaMechanisms){
            if(source.equals(mech.getSource()))
                return Optional.of(mech);
        }
        return Optional.empty();
    }

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
