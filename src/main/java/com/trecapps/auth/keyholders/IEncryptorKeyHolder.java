package com.trecapps.auth.keyholders;

import org.springframework.stereotype.Service;

public interface IEncryptorKeyHolder {

    String getSecret(String secretName);

}
