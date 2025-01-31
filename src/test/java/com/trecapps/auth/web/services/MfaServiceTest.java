package com.trecapps.auth.web.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.models.*;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

@ExtendWith(MockitoExtension.class)
public class MfaServiceTest {
    @InjectMocks
    MfaService mfaService;

    @Mock
    IUserStorageService userStorageService;

    @Mock
    SecretGenerator secretGenerator;

    DefaultSecretGenerator defaultSecretGenerator = new DefaultSecretGenerator();

    @Mock
    QrGenerator qrGenerator;
    ZxingPngQrGenerator defaultQrGenerator = new ZxingPngQrGenerator();

    @Mock
    CodeVerifier codeVerifier;

    TcUser user = ObjectTestProvider.getTcUser();

    void addPhoneMech(){
        MfaMechanism mech = new MfaMechanism();
        mech.setSource("Phone");
        user.getMfaMechanisms().add(mech);
    }

    void addEmailMech(){
        MfaMechanism mech = new MfaMechanism();
        mech.setSource("Email");
        user.getMfaMechanisms().add(mech);
    }

    void addTokenMech(String secret, String name){
        MfaMechanism mech = new MfaMechanism();
        mech.setSource("Token");
        mech.setName((name));
        mech.setUserCode(secret);
        user.getMfaMechanisms().add(mech);
    }

    @Test
    void testGetAvailableMFAOptions(){
        List<String> options = this.mfaService.getAvailableMFAOptions(user);
        Assertions.assertTrue(options.isEmpty());

        addTokenMech("aaaaa", "token_1");
        options = this.mfaService.getAvailableMFAOptions(user);
        Assertions.assertTrue(options.contains("Token"));

        addEmailMech();
        options = this.mfaService.getAvailableMFAOptions(user);
        Assertions.assertTrue(options.contains("Token"));
        Assertions.assertTrue(options.contains("Email"));

        addPhoneMech();
        options = this.mfaService.getAvailableMFAOptions(user);
        Assertions.assertTrue(options.contains("Token"));
        Assertions.assertTrue(options.contains("Email"));
        Assertions.assertTrue(options.contains("Phone"));
    }

    @Test
    void testEnablePhoneVerification(){
        user.setPhoneVerified(false);
        Assertions.assertFalse(mfaService.enablePhoneVerification(user));

        user.setPhoneVerified(true);
        user.setMobilePhone(new PhoneNumber(555555555));

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TcUser pUser = invoke.getArgument(0, TcUser.class);
            Optional<MfaMechanism> mechanismOptional = pUser.getMechanism("Phone");
            Assertions.assertTrue(mechanismOptional.isPresent());
            return null;
        }).when(userStorageService).saveUser(user);
        Assertions.assertTrue(mfaService.enablePhoneVerification(user));
    }

    @Test
    void testEnableEmailVerification(){
        user.setEmailVerified(false);
        Assertions.assertFalse(mfaService.enableEmailVerification(user));

        user.setEmailVerified(true);
        user.setEmail("john.doe@gmail.com");

        Mockito.doAnswer((InvocationOnMock invoke) -> {
            TcUser pUser = invoke.getArgument(0, TcUser.class);
            Optional<MfaMechanism> mechanismOptional = pUser.getMechanism("Email");
            Assertions.assertTrue(mechanismOptional.isPresent());
            return null;
        }).when(userStorageService).saveUser(user);
        Assertions.assertTrue(mfaService.enableEmailVerification(user));
    }

    @Test
    void testSetUpKey(){
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            return this.defaultSecretGenerator.generate();
        }).when(secretGenerator).generate();
        TokenResult token1 = mfaService.setUpKey(user);

        Assertions.assertNotNull(token1);
        List<MfaMechanism> mechs = user.getMfaMechanisms();
        Assertions.assertEquals(1, mechs.size());
        Assertions.assertEquals(token1.tokenCode(), mechs.get(0).getUserCode());
        Assertions.assertEquals("token_1", mechs.get(0).getName());
        Assertions.assertEquals("token_1", token1.name());

        TokenResult token2 = mfaService.setUpKey(user);
        Assertions.assertNotNull(token2);
        mechs = user.getMfaMechanisms();
        Assertions.assertEquals(2, mechs.size());
        Assertions.assertEquals(token2.tokenCode(), mechs.get(1).getUserCode());
        Assertions.assertNotEquals(token1, token2);
        Assertions.assertEquals("token_2", mechs.get(1).getName());
        Assertions.assertEquals("token_2", token2.name());
    }

    @Test
    void testGetQRCode() throws QrGenerationException {
        String tokenName = "token1";
        String userCode = defaultSecretGenerator.generate();
        TokenResult tr = new TokenResult(userCode, tokenName);
        MfaRegistrationData code = mfaService.getQRCode(user, tr);
        Assertions.assertFalse(code.isValid());


        addTokenMech(userCode, tokenName);

        Mockito.doAnswer((InvocationOnMock invoke) ->
                defaultQrGenerator.generate(invoke.getArgument(0, QrData.class)))
                .when(qrGenerator).generate(any(QrData.class));
        Mockito.doAnswer((InvocationOnMock invoke) ->
                        defaultQrGenerator.getImageMimeType())
                .when(qrGenerator).getImageMimeType();

        code = mfaService.getQRCode(user, tr);

        Assertions.assertTrue(code.isValid());
    }

    @Test
    void testVerifyTotp() {
        Mockito.doReturn(false).when(codeVerifier).isValidCode(anyString(), anyString());

        Assertions.assertFalse(mfaService.verifyTotp("code", user));
        addTokenMech(defaultSecretGenerator.generate(), "token_1");
        Assertions.assertFalse(mfaService.verifyTotp("code", user));
        Mockito.doReturn(true).when(codeVerifier).isValidCode(anyString(), anyString());

        Assertions.assertTrue(mfaService.verifyTotp("code", user));

    }

}
