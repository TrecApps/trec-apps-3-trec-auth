package com.trecapps.auth.services.login;

/**
 * Holds Classes that will be useful un managing logins
 *
 * Because Databases have limited connections, it makes sense to have one application manage login
 * functionality - which requires the database connections.
 *
 * Most applications that require authentication can simply use the storage classes to verify jwt tokens and authenticate users
 *
 * @since 0.5.0
 * @author John Jacko
 */