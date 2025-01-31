package com.trecapps.auth.web.services;

import com.trecapps.auth.common.models.MfaMechanism;
import com.trecapps.auth.common.models.MfaRegistrationData;
import com.trecapps.auth.common.models.TcUser;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.util.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@ConditionalOnProperty(prefix = "trecauth.mfa", name = "enabled", havingValue = "true")
public class MfaService {

    @Autowired
    IUserStorageService userStorageService;

    @Autowired
    SecretGenerator secretGenerator;

    @Autowired
    QrGenerator qrGenerator;

    @Autowired
    CodeVerifier codeVerifier;


    public List<String> getAvailableMFAOptions(TcUser user){


        Set<String> ret = new HashSet<>();
        user.getMfaMechanisms().forEach((MfaMechanism mech) -> {
            ret.add(mech.getSource());
        });
        return ret.stream().toList();
    }
    public boolean enablePhoneVerification(TcUser user){
        if(user.isPhoneVerified()){
            Optional<MfaMechanism> oTotp = user.getMechanism("Phone");
            if(oTotp.isEmpty()) {
                MfaMechanism phoneMech = new MfaMechanism();
                phoneMech.setSource("Phone");
                user.getMfaMechanisms().add(phoneMech);
                userStorageService.saveUser(user);
            }
            return true;
        }
        return false;
    }

    public boolean enableEmailVerification(TcUser user){
        if(user.isEmailVerified()){
            Optional<MfaMechanism> oTotp = user.getMechanism("Email");
            if(oTotp.isEmpty()) {
                MfaMechanism phoneMech = new MfaMechanism();
                phoneMech.setSource("Email");
                user.getMfaMechanisms().add(phoneMech);
                userStorageService.saveUser(user);
            }
            return true;
        }
        return false;
    }

    public String setUpKey(TcUser user){
        return setUpKey(user, null);
    }

    public String setUpKey(TcUser user, String name){

        if(user.isMechanismNameTaken(name))
            throw new IllegalArgumentException(String.format("Name %s is already taken", name));

        MfaMechanism totp = new MfaMechanism();
        String backupName = user.callibrateMechanisms();
        totp.setName(name);
        if(!totp.hasName())
            totp.setName(backupName);

        user.getMfaMechanisms().add(totp);
        totp.setSource("Token");


        String ret = secretGenerator.generate();
        totp.setUserCode(ret);
        userStorageService.saveUser(user);
        return ret;
    }

    public MfaRegistrationData getQRCode(TcUser user, String code) throws QrGenerationException {
        Optional<MfaMechanism> oTotp = user.getMechanism("Token");
        if(oTotp.isEmpty()) return new MfaRegistrationData(null, null);

        String userCode = code;

        QrData data = new QrData.Builder().label(user.getUsername())
                .secret(userCode)
                .issuer("Trec-Apps")
                .digits(6)
                .period(30)
                .build();

        String qrCode = Utils.getDataUriForImage(
                qrGenerator.generate(data),
                qrGenerator.getImageMimeType()
        );

        return new MfaRegistrationData(qrCode, userCode);
    }

    public boolean verifyTotp(String code, TcUser user){
        Optional<MfaMechanism> oTotp = user.getMechanism("Token");
        if(oTotp.isEmpty()) return false;

        String userCode = oTotp.get().getUserCode();

        return codeVerifier.isValidCode(userCode, code);
    }
}
