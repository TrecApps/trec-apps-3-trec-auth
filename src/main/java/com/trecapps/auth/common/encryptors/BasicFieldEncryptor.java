package com.trecapps.auth.common.encryptors;

public class BasicFieldEncryptor implements IFieldEncryptor{
    @Override
    public <A> A encrypt(A obj) {
        return obj;
    }

    @Override
    public <A> A decrypt(A obj) {
        return obj;
    }
}
