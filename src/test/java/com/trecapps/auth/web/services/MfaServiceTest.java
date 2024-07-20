package com.trecapps.auth.web.services;

import com.trecapps.auth.ObjectTestProvider;
import com.trecapps.auth.common.models.MfaMechanism;
import com.trecapps.auth.common.models.TcUser;
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

    void addTokenMech(String secret){
        MfaMechanism mech = new MfaMechanism();
        mech.setSource("Token");
        mech.setUserCode(secret);
        user.getMfaMechanisms().add(mech);
    }

    @Test
    void testGetAvailableMFAOptions(){
        List<String> options = this.mfaService.getAvailableMFAOptions(user);
        Assertions.assertTrue(options.isEmpty());

        addTokenMech("aaaaa");
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
    void testSetUpKey(){
        Mockito.doAnswer((InvocationOnMock invoke) -> {
            return this.defaultSecretGenerator.generate();
        }).when(secretGenerator).generate();
        String token1 = mfaService.setUpKey(user);

        Assertions.assertNotNull(token1);
        List<MfaMechanism> mechs = user.getMfaMechanisms();
        Assertions.assertEquals(1, mechs.size());
        Assertions.assertEquals(token1, mechs.get(0).getUserCode());

        String token2 = mfaService.setUpKey(user);
        Assertions.assertNotNull(token2);
        mechs = user.getMfaMechanisms();
        Assertions.assertEquals(1, mechs.size());
        Assertions.assertEquals(token2, mechs.get(0).getUserCode());
        Assertions.assertNotEquals(token1, token2);
    }

    @Test
    void testGetQRCode() throws QrGenerationException {
        String code = mfaService.getQRCode(user);
        Assertions.assertTrue(code.isEmpty());

        addTokenMech(defaultSecretGenerator.generate());

        Mockito.doAnswer((InvocationOnMock invoke) ->
                defaultQrGenerator.generate(invoke.getArgument(0, QrData.class)))
                .when(qrGenerator).generate(any(QrData.class));
        Mockito.doAnswer((InvocationOnMock invoke) ->
                        defaultQrGenerator.getImageMimeType())
                .when(qrGenerator).getImageMimeType();

        code = mfaService.getQRCode(user);

        Assertions.assertFalse(code.isEmpty());
    }

    @Test
    void testVerifyTotp() {
        Mockito.doReturn(false).when(codeVerifier).isValidCode(anyString(), anyString());

        Assertions.assertFalse(mfaService.verifyTotp("code", user));
        addTokenMech(defaultSecretGenerator.generate());
        Assertions.assertFalse(mfaService.verifyTotp("code", user));
        Mockito.doReturn(true).when(codeVerifier).isValidCode(anyString(), anyString());

        Assertions.assertTrue(mfaService.verifyTotp("code", user));

    }

}
