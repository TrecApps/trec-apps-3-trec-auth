package com.trecapps.auth.common;

public interface ISecurityAlertHandler {

    void alertNullAccount(String ipAddress, String path, String query, String method);
}
