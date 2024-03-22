package com.trecapps.auth.encryptors;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class EncryptableFields {
    String field;
    Integer key;
}
