package com.trecapps.auth.encryptors;

import org.springframework.stereotype.Component;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public interface IFieldEncryptor {

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
}
