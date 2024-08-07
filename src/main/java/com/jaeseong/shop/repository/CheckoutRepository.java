package com.jaeseong.shop.repository;

import com.jaeseong.shop.domains.Checkout;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CheckoutRepository extends JpaRepository<Checkout, Integer> {

    Page<Checkout> findPageBy(Pageable page);


    @Query(value = "SELECT c FROM Checkout c JOIN FETCH c.user")
    List<Checkout> customFindAll();

    List<Checkout> findAllByUserId(Integer user_id);

}
