package com.trecapps.auth.encryptors;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RsaFieldEncryptor implements IFieldEncryptor{

    static Class<EncryptedField> encryptedFieldClass = EncryptedField.class;

    @Override
    public <A> A encrypt(A obj) {
        List<EncryptableFields> fieldsList = getEncryptableFields(obj.getClass().getFields());
        return null;
    }

    @Override
    public <A> A decrypt(A obj) {
        List<EncryptableFields> fieldsList = getEncryptableFields(obj.getClass().getFields());
        return null;
    }
}
