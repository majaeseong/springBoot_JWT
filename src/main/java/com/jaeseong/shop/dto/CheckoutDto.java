package com.jaeseong.shop.dto;

import lombok.Data;

@Data
public class CheckoutDto {
    private String itemName;
    private Integer quantity;
    private Integer price;
}
