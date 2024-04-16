package com.trecapps.auth.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trecapps.auth.models.*;
import com.trecapps.auth.services.core.JwtTokenService;
import com.trecapps.auth.services.core.SessionManager;
import com.trecapps.auth.services.core.UserStorageService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/refresh_token")
@ConditionalOnProperty(prefix = "trecauth", name="use-cookie", havingValue = "true")
public class CookieController {

    @GetMapping
    public ResponseEntity<LoginToken> checkRefresh(){
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context == null ? null : context.getAuthentication();

        if(authentication instanceof TrecAuthentication){
            TrecAuthentication tAuth = (TrecAuthentication) authentication;

            ((TrecAuthentication) authentication).setUseCookie(true);
            return new ResponseEntity<>(tAuth.getLoginToken(), HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }





}
