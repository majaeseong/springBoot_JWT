package com.jaeseong.shop.domains;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.ColumnDefault;

import java.util.ArrayList;
import java.util.List;

enum Category {
    item1,
    item2
}

@Entity
@Data
public class Item {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(columnDefinition = "VARCHAR(2048) NOT NULL, FULLTEXT KEY titleFulltext (title)", nullable = false, length = 50)
    private String title;

    @Column(nullable = false)
    @ColumnDefault("0")
    private Integer price;

    @Column()
    @Enumerated(EnumType.STRING)
    private Category category;

    @Column()
    private String seller;


    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name="itemId")
    private List<Comment> comments = new ArrayList<>();

}
