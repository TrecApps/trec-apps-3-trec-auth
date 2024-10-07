package com.trecapps.auth;

import com.trecapps.auth.common.encryptors.EncryptedField;
import lombok.Data;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Data
public class EncryptableTestObj {

    String basicField;

    @EncryptedField
    String encryptedField;

    @EncryptedField
    EncryptableTestObj childObject;

    @EncryptedField
    List<String> listOfStrings = new ArrayList<>();

    @EncryptedField
    Set<String> setOfStrings = new HashSet<>();
}
