package com.trecapps.auth.services.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.keyholders.IJwtKeyHolder;
import com.trecapps.auth.models.*;
import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.repos.primary.TrecAccountRepo;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
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
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Service
@Slf4j
public class JwtTokenService {
	

	@Value("${trecauth.app}")
	String app;
	
	RSAPublicKey publicKey;
	
	RSAPrivateKey privateKey;

	@Autowired
	IUserStorageService userStorageService;

	@Autowired
	SessionManager sessionManager;

	@Autowired
	IJwtKeyHolder jwtKeyHolder;

	private DecodedJWT decodeJWT(String token)
	{
		if(!setKeys())
			return null;
		DecodedJWT ret = null;
		try
		{
			ret = JWT.require(Algorithm.RSA512(publicKey,privateKey))
					.build()
					.verify(token);
		}
		catch(JWTVerificationException e)
		{
			//e.printStackTrace();
			return null;
		}
		return ret;
	}

	// chose a Character random from this String
	final String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			+ "0123456789"
			+ "abcdefghijklmnopqrstuvxyz";
	final int RANDOM_STRING_LENGTH = 10;

	private String generateRandomString()
	{
		StringBuilder sb = new StringBuilder();
		for(int c = 0; c < RANDOM_STRING_LENGTH; c++)
		{
			int ch = (int) (Math.random() * AlphaNumericString.length());
			sb.append(AlphaNumericString.charAt(ch));
		}
		return sb.toString();
	}
	
	private static final long TEN_MINUTES = 600_000;

	private static final long ONE_MINUTE = 60_000;

	private boolean setKeys()
	{
		if(publicKey == null)
		{
			try {
				String encKey = jwtKeyHolder.getPublicKey();

				X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encKey));
				
				publicKey = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);
				
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
					
		}
		
		if(privateKey == null)
		{
			String encKey = jwtKeyHolder.getPrivateKey();
			try (PEMParser parser = new PEMParser(new StringReader(encKey))) {

				        PemObject pemObject = parser.readPemObject();
				        byte[] content = pemObject.getContent();
				        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
				        privateKey =  (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);
			} catch (FileNotFoundException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
		}
		
		return privateKey != null && publicKey != null;
	}

	public TokenTime generateToken(TrecAccount account, String userAgent, TcBrands brand, boolean expires, String app1)
	{
		return generateToken(account, userAgent, brand, null, expires, app1);
	}

	public TokenTime generateToken(TrecAccount account, String userAgent, TcBrands brand, String session, boolean expires, String app1)
	{
		return generateToken(account, userAgent, brand, session, expires, false, app1);
	}

	/**
	 * Use when attempting to log on to User Service directly (through the User Client Project)
	 * @param account
	 * @return
	 */
	public TokenTime generateToken(TrecAccount account, String userAgent, TcBrands brand, String session, boolean expires, boolean useMfa, String app1)
	{
		if(account == null)
			return null;
		
		if(!setKeys())
			return null;


		String userId = account.getId();
		sessionManager.prepNewUser(userId);

		Date now = new Date(Calendar.getInstance().getTime().getTime());

		TokenTime ret = null;
		if(session == null)
			ret = sessionManager.addSession(app1, account.getId(), userAgent, expires);
		else
		{
			ret = new TokenTime();
			ret.setSession(session);

			if(expires)
			{
				OffsetDateTime expiration = OffsetDateTime.now().plus(10, ChronoUnit.MINUTES);
				sessionManager.updateSessionExpiration(account.getId(), session, expiration);
				ret.setExpiration(expiration);
			}
		}

		String useBrand = "null";
		if(brand != null)
		{
			if(brand.getOwners().contains(account.getId())) useBrand = brand.getId().toString();
		}

		JWTCreator.Builder jwtBuilder = JWT.create().withIssuer(app1)
				.withClaim("ID", account.getId())
				.withClaim("Username", account.getUsername())
				.withClaim("Brand", useBrand)
				.withClaim("SessionId", ret.getSession())
				.withIssuedAt(now)
				.withClaim("mfa", useMfa);

		if(ret.getExpiration() != null)
			jwtBuilder = jwtBuilder.withExpiresAt(ret.getExpiration().toInstant());

		ret.setToken(jwtBuilder.sign(Algorithm.RSA512(publicKey, privateKey)));
		return ret;

	}

	public TokenTime addMfa(String token)
	{
		if (token == null)
			return null;
		DecodedJWT decodedJwt = decodeJWT(token);

		if (decodedJwt == null) {
			return null;
		}

		AtomicReference<JWTCreator.Builder> jwtBuilder = new AtomicReference<>(JWT.create());
		AtomicBoolean mfaFound = new AtomicBoolean(false);

		decodedJwt.getClaims().forEach((String claimName, Claim claim) -> {
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
		ret.setToken(jwtBuilder.get().sign(Algorithm.RSA512(publicKey, privateKey)));
		return ret;
	}

	public TokenTime generateNewTokenFromRefresh(String refreshToken)
	{
		DecodedJWT decodedJwt = null;
		try
		{
			decodedJwt = JWT.require(Algorithm.RSA512(publicKey,privateKey))
					.build()
					.verify(refreshToken);
		}
		catch(JWTVerificationException e)
		{
			e.printStackTrace();
			return null;
		}

		String user = decodedJwt.getClaim("ID").asString();
		String session = decodedJwt.getClaim("Session").asString();

		OffsetDateTime newExp = OffsetDateTime.now().plusMinutes(10);
		sessionManager.updateSessionExpiration(user, session, newExp);

		String brand = decodedJwt.getClaim("Brand").asString();
		JWTCreator.Builder jwtBuilder = JWT.create().withIssuer(app)
				.withClaim("ID", user)
				.withClaim("Username", decodedJwt.getClaim("Username").asString())
				.withClaim("Brand", brand)
				.withClaim("SessionId", session)
				.withIssuedAt(OffsetDateTime.now().toInstant())
				.withExpiresAt(newExp.toInstant());

		TokenTime ret = new TokenTime();
		ret.setSession(session);
		ret.setExpiration(newExp);
		ret.setToken(jwtBuilder.sign(Algorithm.RSA512(publicKey, privateKey)));
		return ret;
	}

	public String generateRefreshToken(TrecAccount account)
	{
		if(account == null)
			return null;

		if(!setKeys())
			return null;
		Date now = new Date(Calendar.getInstance().getTime().getTime());

		AtomicReference<JWTCreator.Builder> jwtBuilder = new AtomicReference<>(JWT.create().withIssuer(app)
				.withClaim("ID", account.getId())
				.withClaim("Username", account.getUsername())
				.withClaim("Purpose", "Refresh")
				.withIssuedAt(now));

		return jwtBuilder.get()
				.sign(Algorithm.RSA512(publicKey, privateKey));
	}

	public String getSessionId(String token)
	{
		if(!setKeys() || token== null)
			return null;

		DecodedJWT decodedJwt = null;
		try
		{
			decodedJwt = JWT.require(Algorithm.RSA512(publicKey,privateKey))
					.build()
					.verify(token);
		}
		catch(JWTVerificationException e)
		{
			e.printStackTrace();
			return null;
		}

		Claim idClaim = decodedJwt.getClaim("SessionId");

		return idClaim.asString();
	}

	public DecodedJWT decodeToken(String token){
		if (token == null)
			return null;
		return decodeJWT(token);
	}

	/***
	 * Verifies that a token refers to a specific User Account
	 * @param token
	 * @return
	 */
	public TrecAuthentication verifyToken(DecodedJWT decodedJwt, TokenFlags tokenFlags) {


		if (decodedJwt == null) {
			return null;
		}
		Claim idClaim = decodedJwt.getClaim("ID");

		String idLong = idClaim.asString();


		if (idLong == null) {
			return null;
		}

		String brandStr = decodedJwt.getClaim("Brand").asString();

		Optional<TcUser> ret = userStorageService.getAccountById(idLong);

		if(ret.isEmpty())
			return null;
		TcUser acc = ret.get();

		Claim mfaClaim = decodedJwt.getClaim("mfa");
		if(mfaClaim != null)
			tokenFlags.setIsMfa(mfaClaim.asBoolean());

		TrecAuthentication trecAuthentication = new TrecAuthentication(acc);

		try {
			trecAuthentication.setBrandId(UUID.fromString(brandStr));
		} catch(Throwable ignored)
		{

		}
		return trecAuthentication;
	}

	public Map<String, String> claims(DecodedJWT decodedJwt){
		Map<String, String> ret = new HashMap<>();
		Map<String, Claim> claimMap = decodedJwt.getClaims();

		claimMap.forEach((String n, Claim c) -> {
			if(n.startsWith("app_")){
				ret.put(n, c.asString());
			}
		});
		return ret;
	}
}
