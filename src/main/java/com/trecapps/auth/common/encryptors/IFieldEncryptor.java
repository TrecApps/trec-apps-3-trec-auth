package com.trecapps.auth.common.encryptors;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;


public interface IFieldEncryptor {

    String FRONT_WRAP = "_ENC_(";
    String BACK_WRAP = ")";

    <A> A encrypt(A obj);
    <A> A decrypt(A obj);

    default List<EncryptableFields> getEncryptableFields(Field[] fields){
        List<EncryptableFields> fieldList = new ArrayList<>();
        for(Field field: fields){
            Annotation[] annotations = field.getDeclaredAnnotations();

            for (Annotation a: annotations) {
                if(a instanceof EncryptedField efa)
                {
                    int v = efa.value();
                    fieldList.add(new EncryptableFields(field.getName(), v == 0 ? null : v));
                    break;
                }
            }
        }

        return fieldList;
    }

    default boolean isFieldEncrypted(String f) {
        return f != null && (
                f.startsWith(FRONT_WRAP) && f.endsWith(BACK_WRAP)
                );
    }

    default String wrapField(String f){
        return String.format("%s%s%s", FRONT_WRAP, f, BACK_WRAP);
    }

    default String unwrapField(String f){
        if(!isFieldEncrypted(f)) return f;

        return f.substring(FRONT_WRAP.length(), f.length() - 1);
    }
}
