package com.trecapps.auth.models;

import lombok.Data;

import java.util.Map;

@Data
public class AppLocker {

    Map<String, FailedLoginList> loginListMap;
}
