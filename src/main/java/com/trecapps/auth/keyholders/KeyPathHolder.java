package com.trecapps.auth.keyholders;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class KeyPathHolder {

    String keyPath;
    String key;

    boolean isKeySet(){
        return key != null;
    }
}
