package com.trecapps.auth.models.primary;

import lombok.Data;
import lombok.Getter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Table
@Entity
@Data
public class TrecAccount implements UserDetails {

    @Id
    @GeneratedValue(generator="system-uuid")
    @GenericGenerator(name="system-uuid", strategy = "uuid")
    String id;

    @Column(unique = true)
    String username;

    String passwordHash;

    @Transient
    List<String> authorities;

    @Transient
    UUID brandId;

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
