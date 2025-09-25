//package com.trecapps.auth.web.services;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.messaging.Message;
//import org.springframework.messaging.MessageChannel;
//import org.springframework.messaging.simp.stomp.StompCommand;
//import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
//import org.springframework.messaging.support.ChannelInterceptor;
//import org.springframework.messaging.support.MessageHeaderAccessor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.stereotype.Component;
//
//import java.util.Collections;
//
//@Component
//public class TrecAuthChannelInterceptor implements ChannelInterceptor {
//
//    JwtTokenService jwtService;
//    V2SessionManager sessionManager;
//    IUserStorageService userStorageService;
//
//    String app;
//
//
//    @Autowired
//    public TrecAuthChannelInterceptor(JwtTokenService jwtService1,
//                                      V2SessionManager sessionManager1,
//                                      IUserStorageService userStorageService1,
//                                      @Value("${trecauth.app}") String app1
//                                      ) {
//        sessionManager = sessionManager1;
//        jwtService = jwtService1;
//        userStorageService = userStorageService1;
//        app = app1;
//    }
//
//    @Override
//    public Message<?> preSend(final Message<?> message, final MessageChannel channel) {
//        final StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
//
//        if (StompCommand.CONNECT == accessor.getCommand()) {
//            final String token = accessor.getFirstNativeHeader("Authorization");
//            final String password = accessor.getFirstNativeHeader(PASSWORD_HEADER);
//
//            final UsernamePasswordAuthenticationToken user = webSocketAuthenticatorService.getAuthenticatedOrFail(username, password);
//
//            accessor.setUser(user);
//        }
//        return message;
//    }
//}
