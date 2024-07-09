package com.trecapps.auth.common.models;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class AppLocker {

    Map<String, FailedLoginList> loginListMap = new HashMap<>();
}
