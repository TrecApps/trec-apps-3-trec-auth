package com.trecapps.auth.webflux.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.common.models.*;
import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.primary.TrecAccount;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Service
@Slf4j
public class JwtTokenServiceAsync {
    String app;

//    RSAPublicKey publicKey;
//
//    RSAPrivateKey privateKey;

    IUserStorageServiceAsync userStorageService;

    V2SessionManagerAsync sessionManager;

    IJwtKeyHolder jwtKeyHolder;


    JwtKeyArray keyArray;

    @Autowired
    public JwtTokenServiceAsync(
            IUserStorageServiceAsync userStorageServiceAsync,
            V2SessionManagerAsync sessionManager,
            IJwtKeyHolder jwtKeyHolder,
            JwtKeyArray keyArray1,
            @Value("${trecauth.app}") String app,
            @Value("${trecauth.key.version-count:1}") int versionCount
    ) {
        this.userStorageService = userStorageServiceAsync;
        this.sessionManager = sessionManager;
        this.jwtKeyHolder = jwtKeyHolder;
        this.app = app;
        this.keyArray = keyArray1;
        setKeys(versionCount);
    }

    // chose a Character random from this String
    final String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789"
            + "abcdefghijklmnopqrstuvxyz";
    final int RANDOM_STRING_LENGTH = 10;


    private static final long TEN_MINUTES = 600_000;

    private static final long ONE_MINUTE = 60_000;

    @SneakyThrows
    private void setKeys(int versionCount)
    {
        while(versionCount > 0){
            versionCount--;
            this.keyArray.AddKey(jwtKeyHolder.getPublicKey(versionCount), jwtKeyHolder.getPrivateKey(versionCount));
        }
    }
//
//    public Mono<Optional<TokenTime>> generateToken(TrecAccount account, String userAgent, TcBrands brand, boolean expires, String app1)
//    {
//        return generateToken(account, userAgent, brand, null, expires, app1);
//    }
//
//    public Mono<Optional<TokenTime>> generateToken(TrecAccount account, String userAgent, TcBrands brand, String session, boolean expires, String app1)
//    {
//        return generateToken(account, userAgent, brand, session, expires, false, app1);
//    }

    /**
     * Use when attempting to log on to User Service directly (through the User Client Project)
     * @param account the account to generate a token for
     * @return Mono hosting a possible TokenTime object
     */
    public Mono<Optional<TokenTime>> generateToken(TrecAccount account, String userAgent, TcBrands brand, String app1, TokenOptions tokenOptions)
    {
        if(account == null)
            return Mono.just(Optional.empty());


        String userId = account.getId();

        Date now = new Date(Calendar.getInstance().getTime().getTime());

        Mono<TokenTime> tokenTime;

        if(tokenOptions.getSession() == null)
            tokenTime = sessionManager.addSession(app1, account.getId(), userAgent, tokenOptions.isExpires());
        else
        {
            tokenTime = Mono.just(new TokenTime())
                    .flatMap((TokenTime ret) -> {

                        ret = new TokenTime();
                        ret.setSession(tokenOptions.getSession());

                        if(tokenOptions.isExpires())
                        {
                            OffsetDateTime expiration = OffsetDateTime.now().plusMinutes(10);
                            return sessionManager.updateSessionExpiration(account.getId(), tokenOptions.getSession(), expiration)
                                    .then(Mono.just(ret))
                                    .doOnNext((TokenTime t) -> t.setExpiration(expiration));
                        }
                        return Mono.just(ret);
                    });

        }

        return tokenTime.doOnNext((TokenTime ret) -> {

                String useBrand = "null";
                if(brand != null)
                {
                    if(brand.getOwners().contains(account.getId())) useBrand = brand.getId();
                }

                JWTCreator.Builder jwtBuilder = JWT.create().withIssuer(app1)
                        .withClaim("ID", account.getId())
                        .withClaim("Username", account.getUsername())
                        .withClaim("Brand", useBrand)
                        .withClaim("SessionId", ret.getSession())
                        .withIssuedAt(now)
                        .withClaim("mfa", tokenOptions.isUseMfa());

                if(ret.getExpiration() != null)
                    jwtBuilder = jwtBuilder.withExpiresAt(ret.getExpiration().toInstant());
                if(tokenOptions.isNeedsMfa())
                    jwtBuilder = jwtBuilder.withClaim("needsMfa", true);
                ret.setToken(keyArray.encodeJWT(jwtBuilder));


        }).map(Optional::of);

    }

    public TokenTime addMfa(String token)
    {
        if (token == null)
            return null;
        JwtKeyArray.DecodedHolder decodedJwt = keyArray.decodeJwt(token);

        if (decodedJwt.getDecodedJwt().isEmpty()) {
            return null;
        }

        AtomicReference<JWTCreator.Builder> jwtBuilder = new AtomicReference<>(JWT.create());
        AtomicBoolean mfaFound = new AtomicBoolean(false);

        decodedJwt.getDecodedJwt().get().getClaims().forEach((String claimName, Claim claim) -> {
            if("mfa".equals(claimName))
            {
                mfaFound.set(true);
                jwtBuilder.set(jwtBuilder.get().withClaim(claimName, true));
            }
            else {
                java.util.Date date = claim.asDate();
                Instant instant = claim.asInstant();
                Boolean bool = claim.asBoolean();
                if(date != null)
                    jwtBuilder.set(jwtBuilder.get().withClaim(claimName,date));
                else if(instant != null)
                    jwtBuilder.set(jwtBuilder.get().withClaim(claimName,instant));
                else if(bool != null)
                    jwtBuilder.set(jwtBuilder.get().withClaim(claimName,bool));
                else
                    jwtBuilder.set(jwtBuilder.get().withClaim(claimName,claim.asString()));
            }
        });

        if(!mfaFound.get())
        {
            jwtBuilder.set(jwtBuilder.get().withClaim("mfa", true));
        }
        TokenTime ret = new TokenTime();
        ret.setToken(keyArray.encodeJWT(jwtBuilder.get()));
        ret.setOldToken(decodedJwt.isKeyOutdated());
        return ret;
    }

    public Mono<TokenTime> generateNewTokenFromRefresh(String refreshToken)
    {
        JwtKeyArray.DecodedHolder decodedJwtHolder = keyArray.decodeJwt(refreshToken);
        if(decodedJwtHolder.getDecodedJwt().isEmpty())
            return Mono.empty();

        DecodedJWT decodedJwt = decodedJwtHolder.getDecodedJwt().get();

        String user = decodedJwt.getClaim("ID").asString();
        String session = decodedJwt.getClaim("SessionId").asString();

        OffsetDateTime newExp = OffsetDateTime.now().plusMinutes(10);
        DecodedJWT finalDecodedJwt = decodedJwt;
        return sessionManager.updateSessionExpiration(user, session, newExp)
                .then(Mono.just(new TokenTime()))
                .map((TokenTime ret) -> {
                    String brand = finalDecodedJwt.getClaim("Brand").asString();
                    JWTCreator.Builder jwtBuilder = JWT.create().withIssuer(app)
                            .withClaim("ID", user)
                            .withClaim("Username", finalDecodedJwt.getClaim("Username").asString())
                            .withClaim("Brand", brand)
                            .withClaim("SessionId", session)
                            .withIssuedAt(OffsetDateTime.now().toInstant())
                            .withExpiresAt(newExp.toInstant());

                    ret.setSession(session);
                    ret.setExpiration(newExp);
                    ret.setToken(keyArray.encodeJWT(jwtBuilder));
                    ret.setOldToken(decodedJwtHolder.isKeyOutdated());
                    return ret;
                });


    }

    public String generateRefreshToken(TrecAccount account, String sessionId)
    {
        if(account == null)
            return null;

        Date now = new Date(Calendar.getInstance().getTime().getTime());

        AtomicReference<JWTCreator.Builder> jwtBuilder = new AtomicReference<>(JWT.create().withIssuer(app)
                .withClaim("ID", account.getId())
                .withClaim("Username", account.getUsername())
                .withClaim("Purpose", "Refresh")
                .withClaim("SessionId", sessionId)
                .withIssuedAt(now));

        return keyArray.encodeJWT(jwtBuilder.get());
    }

    public String getSessionId(String token)
    {
        JwtKeyArray.DecodedHolder decodedJwt = keyArray.decodeJwt(token);
        if(decodedJwt.getDecodedJwt().isEmpty())
            return null;

        Claim idClaim = decodedJwt.getDecodedJwt().get().getClaim("SessionId");

        return idClaim.asString();
    }

    public JwtKeyArray.DecodedHolder decodeToken(String token){
        return keyArray.decodeJwt(token);
    }

    /***
     * Verifies that a token refers to a specific User Account
     * @param token
     * @return
     */
    public Mono<Optional<TrecAuthentication>> verifyToken(DecodedJWT decodedJwt, TokenFlags tokenFlags) {


        if (decodedJwt == null) {
            return null;
        }
        Claim idClaim = decodedJwt.getClaim("ID");

        String idLong = idClaim.asString();


        if (idLong == null) {
            return null;
        }

        String brandStr = decodedJwt.getClaim("Brand").asString();

        return userStorageService.getAccountById(idLong)
                .flatMap((Optional<TcUser> oUser) -> {
                    if(oUser.isPresent()){
                        TcUser acc = oUser.get();

                        Claim mfaClaim = decodedJwt.getClaim("mfa");
                        if(mfaClaim != null)
                            tokenFlags.setIsMfa(mfaClaim.asBoolean());

                        TrecAuthentication trecAuthentication = new TrecAuthentication(acc);

                        Claim sessionIdClaim = decodedJwt.getClaim("SessionId");
                        Claim needsMfa = decodedJwt.getClaim("needsMfa");

                        trecAuthentication.setNeedsMfa(Boolean.TRUE.equals(needsMfa.asBoolean()));

                        trecAuthentication.setSessionId(sessionIdClaim.asString());

                        if(brandStr != null && !"null".equals(brandStr))
                        {
                            if(!acc.getBrands().contains(brandStr))
                                throw new RuntimeException("User does not own the target Brand Account");
                            return userStorageService.getBrandById(brandStr)
                                    .map((Optional<TcBrands> oBrands) -> {
                                        oBrands.ifPresent(trecAuthentication::setBrand);
                                        return Optional.of(trecAuthentication);
                                    });
                        }
                        return Mono.just(Optional.of(trecAuthentication));
                    }
                    else return Mono.just(Optional.empty());
                });
    }

//    public Map<String, String> claims(DecodedJWT decodedJwt){
//        Map<String, String> ret = new HashMap<>();
//        Map<String, Claim> claimMap = decodedJwt.getClaims();
//
//        claimMap.forEach((String n, Claim c) -> {
//            if(n.startsWith("app_")){
//                ret.put(n, c.asString());
//            }
//        });
//        return ret;
//    }
}
