package com.trecapps.auth.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trecapps.auth.models.TcBrands;
import com.trecapps.auth.models.primary.TrecAccount;
import com.trecapps.auth.repos.primary.TrecAccountRepo;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Calendar;
import java.util.Optional;
import java.util.Scanner;

@Service
public class JwtTokenService {
	
	@Value("${trec.key.public}")
	String publicKeyStr;
	
	@Value("${trec.key.private}")
	String privateKeyStr;

	@Value("${trecauth.app}")
	String app;
	
	RSAPublicKey publicKey;
	
	RSAPrivateKey privateKey;
	
	@Autowired
	TrecAccountService accountService;
	
	@Autowired
	TrecAccountRepo accountRepo;


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
			e.printStackTrace();
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
			File publicFile = new File(publicKeyStr);

			Scanner keyfis;
			try {
				String encKey = "";
				
				keyfis = new Scanner(publicFile);
				
				while(keyfis.hasNext())
				{
					encKey += keyfis.next();
				}
				
				keyfis.close();
				
				X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encKey));
				
				publicKey = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);
				
			} catch (FileNotFoundException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
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
			File privateFile = new File(privateKeyStr);
			
			try (FileReader keyReader = new FileReader(privateFile);
				      PemReader pemReader = new PemReader(keyReader)) {
				 
				        PemObject pemObject = pemReader.readPemObject();
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

	/**
	 * Use when attempting to log on to User Service directly (through the User Client Project)
	 * @param account
	 * @return
	 */
	public String generateToken(TrecAccount account, TcBrands brand)
	{
		if(account == null)
			return null;
		
		if(!setKeys())
			return null;
		
//		if(!verifyUnlocked(account))
//			return null;
		
		privateKey.getAlgorithm();
		
		Date now = new Date(Calendar.getInstance().getTime().getTime());

		return JWT.create().withIssuer(app)
				.withClaim("ID", account.getId())
				.withClaim("Username", account.getUsername())
				.withClaim("Brand", brand == null ? "null" : brand.getId().toString())
				.withIssuedAt(now)
				.sign(Algorithm.RSA512(publicKey, privateKey));

	}

	public String getSessionId(String token)
	{
		if(!setKeys())
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

		Claim idClaim = decodedJwt.getClaim("sessionId");

		return idClaim.asString();
	}

	/***
	 * Verifies that a token refers to a specific User Account
	 * @param token
	 * @return
	 */
	public TrecAccount verifyToken(String token)
	{
		DecodedJWT decodedJwt = decodeJWT(token);

		if(decodedJwt == null) {
			return null;
		}
		Claim idClaim = decodedJwt.getClaim("ID");
		
		String idLong = idClaim.asString();
		
		if(idLong == null) {
			return null;
		}

		Optional<TrecAccount> ret = accountService.getAccountById(idLong);
		
		return ret.isPresent() ? ret.get() : null;
	}


}
