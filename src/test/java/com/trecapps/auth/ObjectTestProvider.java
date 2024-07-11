package com.trecapps.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trecapps.auth.common.models.TcBrands;
import com.trecapps.auth.common.models.TcUser;
import lombok.SneakyThrows;

import java.util.Set;

public class ObjectTestProvider {

    public static TcUser getTcUser(){
        TcUser user = new TcUser();

        user.setId("id");

        user.setBirthdaySetting("PUBLIC");
        user.setDisplayName("John Doe");
        user.setEmail("john.doe@gmail.com");
        return user;
    }

    public static TcBrands getBrand(){
        TcBrands brand = new TcBrands();

        brand.setId("id");
        brand.setName("Trec-Apps");
        brand.setOwners(Set.of("id"));
        return brand;
    }

    @SneakyThrows
    public static <T> byte[] convertObjects(T object, ObjectMapper mapper){
        return mapper.writeValueAsBytes(object);
    }
}
