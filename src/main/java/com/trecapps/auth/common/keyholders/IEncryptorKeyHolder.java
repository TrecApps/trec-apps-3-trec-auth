package com.trecapps.auth.common.keyholders;

import org.springframework.stereotype.Service;

public interface IEncryptorKeyHolder {

    String getSecret(String secretName);

}
