package com.trecapps.auth.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretAsyncClient;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.trecapps.auth.models.KeyPair;
import com.trecapps.auth.models.TcBrands;
import com.trecapps.auth.models.TokenTime;
import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.repos.primary.TrecAccountRepo;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
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
import java.sql.Timestamp;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class JwtTokenService {
	
	@Value("${trec.key.public}")
	String publicKeyStr;
	
	@Value("${trec.key.private}")
	String privateKeyStr;

	@Value("${trecauth.app}")
	String app;

	@Value("&{trecauth.key-vault.url}")
	String keyVaultUrl;

	@Value("&{trecauth.key-vault.primary}")
	String primarySource;
	@Value("${trecauth.key-vault.secondary}")
	String secondarySource;

	KeyPair primaryKey;
	KeyPair secondaryKey;
	
	@Autowired
	TrecAccountService accountService;
	
	@Autowired
	TrecAccountRepo accountRepo;

	@Autowired
	UserStorageService userStorageService;

	@Autowired
	SessionManager sessionManager;

	SecretClient secretClient;

	boolean setKeysWithKeyVault(){
		if(secretClient == null) {
			secretClient = new SecretClientBuilder()
					.vaultUrl(keyVaultUrl)
					.credential(new DefaultAzureCredentialBuilder().build())
					.buildClient();
		}



		try {
			// Primary Public Key
			KeyPair prim = new KeyPair();
			KeyVaultSecret secret = secretClient.getSecret(String.format("%s-public", primarySource));
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(secret.getValue()));
			prim.setPublicKey ((RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(pubKeySpec));

			// Primary Private Key
			secret = secretClient.getSecret(String.format("%s-private", primarySource));
			try (PEMParser parser = new PEMParser(new StringReader(secret.getValue()))) {

				PemObject pemObject = parser.readPemObject();
				byte[] content = pemObject.getContent();
				PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
				prim.setPrivateKey  ((RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privKeySpec));
			}

			// Secondary Public Key
			KeyPair secPair = new KeyPair();
			secret = secretClient.getSecret(String.format("%s-public", secondarySource));
			pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(secret.getValue()));
			secPair.setPublicKey ((RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(pubKeySpec));

			secret = secretClient.getSecret(String.format("%s-private", secondarySource));
			try (PEMParser parser = new PEMParser(new StringReader(secret.getValue()))) {

				PemObject pemObject = parser.readPemObject();
				byte[] content = pemObject.getContent();
				PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
				secPair.setPrivateKey  ((RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privKeySpec));
			}

			this.primaryKey = prim;
			this.secondaryKey = secPair;

		}catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return primaryKey != null && secondaryKey != null;
	}

	private DecodedJWT decodeJWT(String token)
	{
		if(!setKeysWithKeyVault())
			return null;
		DecodedJWT ret = null;
		try
		{
			ret = JWT.require(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey()))
					.build()
					.verify(token);
		}
		catch(JWTVerificationException e)
		{
			try
			{
				ret = JWT.require(Algorithm.RSA512(secondaryKey.getPublicKey(), secondaryKey.getPrivateKey()))
						.build()
						.verify(token);
			}
			catch(JWTVerificationException e2)
			{
				e2.printStackTrace();
				return null;
			}
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

	public TokenTime generateToken(TrecAccount account, String userAgent, TcBrands brand, boolean expires)
	{
		return generateToken(account, userAgent, brand, null, expires);
	}

	/**
	 * Use when attempting to log on to User Service directly (through the User Client Project)
	 * @param account
	 * @return
	 */
	public TokenTime generateToken(TrecAccount account, String userAgent, TcBrands brand, String session, boolean expires)
	{
		if(account == null)
			return null;
		
		if(!setKeysWithKeyVault())
			return null;


		String userId = account.getId();
		sessionManager.prepNewUser(userId);

		Date now = new Date(Calendar.getInstance().getTime().getTime());

		TokenTime ret = null;
		if(session == null)
			ret = sessionManager.addSession(app, account.getId(), userAgent, expires);
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
		JWTCreator.Builder jwtBuilder = JWT.create().withIssuer(app)
				.withClaim("ID", account.getId())
				.withClaim("Username", account.getUsername())
				.withClaim("Brand", brand == null ? "null" : brand.getId().toString())
				.withClaim("SessionId", ret.getSession())
				.withIssuedAt(now);

		if(ret.getExpiration() != null)
			jwtBuilder = jwtBuilder.withExpiresAt(ret.getExpiration().toInstant());

		ret.setToken(jwtBuilder.sign(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey())));
		return ret;

	}

	public TokenTime generateNewTokenFromRefresh(String refreshToken)
	{
		DecodedJWT decodedJwt = null;
		try
		{
			decodedJwt = JWT.require(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey()))
					.build()
					.verify(refreshToken);
		}
		catch(JWTVerificationException e)
		{
			try
			{
				decodedJwt = JWT.require(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey()))
					.build()
					.verify(refreshToken);
			}
			catch(JWTVerificationException e2)
			{
			e2.printStackTrace();
			return null;}
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
		ret.setToken(jwtBuilder.sign(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey())));
		return ret;
	}

	public String generateRefreshToken(TrecAccount account, String brand, String session)
	{
		if(account == null)
			return null;

		if(!setKeysWithKeyVault())
			return null;
		Date now = new Date(Calendar.getInstance().getTime().getTime());
		return JWT.create().withIssuer(app)
				.withClaim("ID", account.getId())
				.withClaim("Username", account.getUsername())
				.withClaim("Purpose", "Refresh")
				.withClaim("Brand", brand == null ? "null" : brand)
				.withClaim("Session", session)
				.withIssuedAt(now)
				.sign(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey()));
	}

	public String getSessionId(String token)
	{
		if(!setKeysWithKeyVault() || token== null)
			return null;

		DecodedJWT decodedJwt = null;
		try
		{
			decodedJwt = JWT.require(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey()))
					.build()
					.verify(token);
		}
		catch(JWTVerificationException e)
		{
			try
			{
				decodedJwt = JWT.require(Algorithm.RSA512(primaryKey.getPublicKey(), primaryKey.getPrivateKey()))
						.build()
						.verify(token);
			}
			catch(JWTVerificationException e2)
			{
				e2.printStackTrace();
				return null;
			}
		}

		Claim idClaim = decodedJwt.getClaim("SessionId");

		return idClaim.asString();
	}

	/***
	 * Verifies that a token refers to a specific User Account
	 * @param token
	 * @return
	 */
	public TrecAccount verifyToken(String token) {
		if (token == null)
			return null;
		DecodedJWT decodedJwt = decodeJWT(token);

		if (decodedJwt == null) {
			return null;
		}
		Claim idClaim = decodedJwt.getClaim("ID");

		String idLong = idClaim.asString();


		if (idLong == null) {
			return null;
		}

		String brandStr = decodedJwt.getClaim("Brand").asString();

		Optional<TrecAccount> ret = accountService.getAccountById(idLong);

		if(ret.isEmpty())
			return null;
		TrecAccount acc = ret.get();

		try {
			acc.setBrandId(UUID.fromString(brandStr));
		} catch(Throwable ignored)
		{

		}
		return acc;
	}
}
