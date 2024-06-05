package com.trecapps.auth.web.controllers;

import com.trecapps.auth.common.models.LoginToken;
import com.trecapps.auth.common.models.TrecAuthentication;

import com.trecapps.auth.web.services.JwtTokenService;
import com.trecapps.auth.web.services.V2SessionManager;
import com.trecapps.auth.web.services.TrecCookieSaver;
import com.trecapps.auth.web.services.IUserStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/refresh_token")
@ConditionalOnProperty(prefix = "trecauth", name="use-cookie", havingValue = "true")
public class CookieController extends TrecCookieSaver {

    @Autowired

    protected CookieController(
            V2SessionManager sessionManager1,
            JwtTokenService tokenService1,
            IUserStorageService userStorageService1,
            @Value("${trecauth.app}") String app1) {
        super(sessionManager1, tokenService1, userStorageService1, app1);
    }

    @GetMapping
    public ResponseEntity<LoginToken> checkRefresh(@RequestHeader("User-Agent") String userClient){
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context == null ? null : context.getAuthentication();

        if(authentication instanceof TrecAuthentication tAuth){

            tAuth.setUseCookie(true);

            this.prepLoginTokens(tAuth, userClient);

            return new ResponseEntity<>(tAuth.getLoginToken(), HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }





}
