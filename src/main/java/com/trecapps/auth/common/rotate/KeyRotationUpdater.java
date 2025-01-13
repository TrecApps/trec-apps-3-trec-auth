package com.trecapps.auth.common.rotate;

import com.trecapps.auth.common.keyholders.IJwtKeyHolder;
import com.trecapps.auth.common.models.JwtKeyArray;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "trecauth.rotate", name = "do-rotate", havingValue = "true")
public class KeyRotationUpdater implements Job {

    @Autowired
    IJwtKeyHolder iJwtKeyHolder;
    @Autowired
    JwtKeyArray jwtKeyArray;

    @Override
    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {
        try {
            String publicKey= iJwtKeyHolder.getPublicKey();
            String privateKey = iJwtKeyHolder.getPrivateKey();
            jwtKeyArray.AddKey(publicKey, privateKey);
        } catch(Exception e) {

        }
    }
}
