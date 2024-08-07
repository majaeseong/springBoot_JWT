package com.jaeseong.shop.repository;

import com.jaeseong.shop.domains.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommentRepository extends JpaRepository<Comment, Integer> {

}
