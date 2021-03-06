package com.trecapps.auth.models;

import lombok.Data;

import java.util.UUID;

@Data
public class TcBrands {

    // Should hold the IDs of the TcUsers that own it
    String[] owners;

    // Display name for the Brand
    String name;
    String profile;

    // ID of the Brand
    UUID id;
}
