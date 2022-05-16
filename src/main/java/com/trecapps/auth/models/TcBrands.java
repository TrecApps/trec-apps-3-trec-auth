package com.trecapps.auth.models;

import lombok.Data;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Data
@Component
public class TcBrands {

    // Should hold the IDs of the TcUsers that own it
    String[] owners;

    // Display name for the Brand
    String name;
    String profile;

    // ID of the Brand
    UUID id;
}
