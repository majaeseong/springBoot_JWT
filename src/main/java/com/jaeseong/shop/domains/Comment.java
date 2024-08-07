package com.jaeseong.shop.domains;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Comment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String content;

//    @ManyToOne()
//    @JoinColumn(name = "user_id")
//    private Member user;

    private Integer userId;
    private Integer itemId;


}
