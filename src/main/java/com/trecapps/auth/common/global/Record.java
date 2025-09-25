package com.trecapps.auth.common.global;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.trecapps.auth.common.models.TcBrands;
import com.trecapps.auth.common.models.TcUser;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class Record implements Comparable<Record> {

    String id;
    String contentId; // Used when stored as separate entities

    String type;

    String userId;
    String brandId;
    String displayName;

    @JsonFormat(pattern="dd/MM/yyyy HH:mm:ss Z")
    OffsetDateTime date;
    RecordEvent event;

    String comment;

    Integer points;

    public void setMaker(@NotNull TcUser user, @Nullable TcBrands brands){
        this.userId = user.getId();
        if(brands == null)
            this.displayName = user.getDisplayName();
        else {
            this.displayName = brands.getName();
            this.brandId = brands.getId();
        }
    }

    @Override
    public int compareTo(Record o) {
        return date.compareTo(o.date);
    }
}
