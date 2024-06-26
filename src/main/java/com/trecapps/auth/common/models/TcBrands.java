package com.trecapps.auth.common.models;

import lombok.Data;

import java.util.Set;
import java.util.UUID;

@Data
public class TcBrands {
    Integer partition; // Used for applying a Profile to the TcUser id on Azure Cosmos DB - Gremlin Service

    // Should hold the IDs of the TcUsers that own it
    Set<String> owners;

    // Display name for the Brand
    String name;
    String profile;

    // ID of the Brand
    String id;
    String infoId; // If there is a BrandInfo entry associated with this Brand
}
