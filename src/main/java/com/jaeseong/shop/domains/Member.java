package com.jaeseong.shop.domains;

import jakarta.persistence.*;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Entity
@Data
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true)
    private String username;

    @Column()
    private String password;

    @Column()
    private String displayName;

    @ToString.Exclude
    @OneToMany(mappedBy = "user")
    List<Checkout> checkouts = new ArrayList<>();

}
