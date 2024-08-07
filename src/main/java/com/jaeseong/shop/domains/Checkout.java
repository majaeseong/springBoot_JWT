package com.jaeseong.shop.domains;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Data
public class Checkout {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column()
    private String itemName;

    @Column()
    private Integer price;

    @Column()
    private Integer quantity;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @ManyToOne()
    @JoinColumn(name = "user_id")
    private Member user;

}
