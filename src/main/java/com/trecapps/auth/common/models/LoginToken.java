package com.trecapps.auth.common.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class LoginToken {

    String access_token, token_type, refresh_token, id_token;

    int expires_in;
}
