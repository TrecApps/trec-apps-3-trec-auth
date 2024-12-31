package com.trecapps.auth.common.models;

import java.util.LinkedList;
import java.util.List;

public class LimitList<E> extends LinkedList<E> {
    int maxCount;

    public LimitList(int maxCount) {
        this.maxCount = maxCount;
    }

    public LimitList(){
        this(2);
    }

    public LimitList(List<E> collection){
        super(collection);
        this.maxCount = 2;
    }

    public LimitList(List<E> collection, int maxCount){
        super(collection.stream().limit(maxCount).toList());
        this.maxCount = maxCount;
    }

    public LimitList(LimitList<E> list){
        super(list);
        this.maxCount = list.maxCount;
    }

    @Override
    public boolean add(E item){
        super.add(item);
        while(size() > maxCount){
            removeFirst();
        }
        return true;
    }

    @Override
    public void add(int index, E item){
        if(index == 0 && size() == maxCount)
            removeFirst();
        super.add(index, item);
        while(size() > maxCount){
            removeFirst();
        }
    }
}
