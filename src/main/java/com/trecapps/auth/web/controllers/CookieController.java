package com.trecapps.auth.web.controllers;

import com.trecapps.auth.common.models.LoginToken;
import com.trecapps.auth.common.models.MfaReq;
import com.trecapps.auth.common.models.TcUser;
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
import org.springframework.web.bind.annotation.*;

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

    boolean isMfaRequired(TcUser user, String app) {
        for(MfaReq req: user.getMfaRequirements())
        {
            if(app.equals(req.getApp()))
                return req.isRequireMfa();
        }
        return false;
    }

    @GetMapping
    public ResponseEntity<LoginToken> checkRefresh(@RequestHeader("User-Agent") String userClient, @RequestParam("app")String app){
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context == null ? null : context.getAuthentication();

        if(authentication instanceof TrecAuthentication tAuth){

            tAuth.setUseCookie(true);

            this.prepLoginTokens(tAuth, userClient);

            sessionManager.setBrand(tAuth.getAccount().getId(), tAuth.getSessionId(), null, this.app, false);
            LoginToken ret = tAuth.getLoginToken();
            if(isMfaRequired(tAuth.getUser(), app))
                ret.setToken_type("User-requires_mfa");


            return new ResponseEntity<>(tAuth.getLoginToken(), HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }





}
