package com.trecapps.auth.common.models.primary;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Table
@Entity
@javax.persistence.Entity
@Data
public class TrecAccount implements UserDetails {

    @Id
    @javax.persistence.Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;

    @Column(unique = true)
    String username;

    String passwordHash;

    @Transient
    List<String> authorities;

    @Transient
    UUID brandId;

    transient byte invalid = (byte)1;

    public boolean isInvalid(){
        return invalid < 1;
    }

    public boolean makeNull(){
        return invalid == 0;
    }

    public static TrecAccount getInvalidAccount(boolean makeNull){
        TrecAccount ret = new TrecAccount();
        ret.invalid = (byte) (makeNull ? 0 : -1);
        return ret;
    }

    public TrecAccount()
    {
        authorities = new ArrayList<>();
    }

    public void addAuthority(String auth)
    {
        authorities.add(auth);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        List<GrantedAuthority> ret = new ArrayList<>();
        if(authorities != null)
            for(String authority: authorities)
            {
                ret.add(new GrantedAuthority() {
                    @Override
                    public String getAuthority() {
                    return authority;
                }
                });
            }
        return ret;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username;
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
