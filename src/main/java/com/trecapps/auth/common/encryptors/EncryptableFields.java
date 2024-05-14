package com.trecapps.auth.common.encryptors;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class EncryptableFields {
    String field;
    Integer key;
}
