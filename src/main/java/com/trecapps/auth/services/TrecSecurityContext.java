package com.trecapps.auth.services;

import com.trecapps.auth.models.TrecAuthentication;
import com.trecapps.auth.models.primary.TrecAccount;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class TrecSecurityContext implements SecurityContextRepository {

    @Autowired
    JwtTokenService jwtService;

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {


        HttpServletRequest req = requestResponseHolder.getRequest();
        SecurityContext ret = getContextFromCookie(req);
        if(ret == null)
            return SecurityContextHolder.createEmptyContext();

        if(ret.getAuthentication() == null)
            ret = getContextFromHeader(req);

        return ret;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        Cookie cook;
        if(!(context.getAuthentication() instanceof TrecAuthentication))
        {
            cook = new Cookie("TRECSESSION", null);
            cook.setSecure(true);
            cook.setMaxAge(0);
        }
        else
        {
            TrecAuthentication trecAuth = (TrecAuthentication) context.getAuthentication();

            // Cookie will have been set by the endpoint!
            if(!trecAuth.isRegularSession())
                return;

            if (trecAuth == null) {
                cook = new Cookie("TRECSESSION", null);
                cook.setMaxAge(0);
            } else {
                cook = new Cookie("TRECSESSION", jwtService.generateToken(trecAuth.getAccount(), null));
                cook.setMaxAge(-1);

            }
        }
        cook.setSecure(true);
        cook.setPath("/");
        response.addCookie(cook);

        if(cook.getValue() != null)
            response.addHeader("SetAuth", cook.getValue());

    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return getContextFromCookie(request) != null;
    }

    SecurityContext getContextFromHeader(HttpServletRequest request)
    {
        String auth = request.getHeader("Authorization");
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        TrecAccount acc = jwtService.verifyToken(auth);
        if(acc == null)
            return context;

        TrecAuthentication tAuth = new TrecAuthentication(acc);
        context.setAuthentication(tAuth);
        return context;
    }

    SecurityContext getContextFromCookie(HttpServletRequest request)
    {
        Cookie[] cookies = request.getCookies();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        if(cookies == null) {
            return context;
        }
        for(Cookie c: cookies)
        {
            String name = c.getName();
            if(name.equals("TRECSESSION"))
            {
                String data = c.getValue();
                TrecAccount acc = jwtService.verifyToken(data);
                if(acc == null)
                    return context;

                TrecAuthentication tAuth = new TrecAuthentication(acc);
                context.setAuthentication(tAuth);
                return context;
            }
        }

        return context;
    }

}
