package com.jaeseong.shop.repository;

import com.jaeseong.shop.domains.Item;
import com.jaeseong.shop.domains.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Integer> {

    boolean existsByUsername(String username);

    Optional<Member> findByUsername(String username);
}
