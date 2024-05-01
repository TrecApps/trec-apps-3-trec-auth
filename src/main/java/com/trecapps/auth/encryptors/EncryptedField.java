package com.trecapps.auth.encryptors;

import java.lang.annotation.*;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptedField {
    int value() default 0;
}
