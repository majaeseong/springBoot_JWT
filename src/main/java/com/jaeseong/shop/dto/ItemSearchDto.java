package com.jaeseong.shop.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ItemSearchDto {
    String keyword="";
    int size=10;
    int index=0;

}
