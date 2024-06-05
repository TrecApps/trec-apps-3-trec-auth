package com.trecapps.auth.common.keyholders;

public interface IEncryptorKeyHolder {

    String getSecret(String secretName);

}
