package com.jaeseong.shop.repository;

import com.jaeseong.shop.domains.Item;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ItemRepository extends JpaRepository<Item, Integer> {

    Page<Item> findPageBy(Pageable page);

    Page<Item> findPageByTitleContains(Pageable page, String title);
}
