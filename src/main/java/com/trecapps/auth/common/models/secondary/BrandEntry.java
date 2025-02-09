package com.trecapps.auth.common.models.secondary;

import com.trecapps.auth.common.models.TcBrands;
import jakarta.persistence.*;
import lombok.Data;

@Table(name = "brandentry")
@Entity
@Data
public class BrandEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;

    String creator;

    String name;

    public static BrandEntry getInstance(TcBrands obj, String creator){
        BrandEntry ret = new BrandEntry();
        ret.setId(obj.getId());
        ret.setName(obj.getName());
        ret.setCreator(creator);
        return ret;
    }
}
