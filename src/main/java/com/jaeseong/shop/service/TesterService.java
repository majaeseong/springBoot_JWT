package com.jaeseong.shop.service;

import com.jaeseong.shop.domains.Comment;
import com.jaeseong.shop.domains.CustomUser;
import com.jaeseong.shop.domains.Item;
import com.jaeseong.shop.dto.AddCommentDto;
import com.jaeseong.shop.dto.ItemSearchDto;
import com.jaeseong.shop.repository.CommentRepository;
import com.jaeseong.shop.repository.ItemRepository;
import com.jaeseong.shop.repository.MemberRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TesterService {

    private final ItemRepository itemRepository;
    private final MemberRepository memberRepository;
    private final CommentRepository commentRepository;


    public Page<Item> getItems(ItemSearchDto dto){

        Page<Item> result  = dto.getKeyword().isEmpty() ? itemRepository.findPageBy(PageRequest.of(dto.getIndex(),dto.getSize())) : itemRepository.findPageByTitleContains(PageRequest.of(dto.getIndex(),dto.getSize()) , dto.getKeyword());

        return result;
    }

    public Item getItemById(Integer id) throws Exception {

        var result = itemRepository.findById(id);
        if(result.isPresent()){
            System.out.println(result.get().getComments());
            return result.get();
        }else{
            throw new Exception("Not found");
        }

    }

    public void saveItem(Item dto, String username){

        dto.setSeller(username);
        itemRepository.save(dto);
    }

    public void updateItem(Item dto){
        itemRepository.save(dto);
    }

    public void deleteById(Integer id){
        itemRepository.deleteById(id);
    }

    public void saveComment(AddCommentDto dto, Authentication auth){

        CustomUser customUser = (CustomUser) auth.getPrincipal();

        var user = memberRepository.findById(customUser.getId());
        var item = itemRepository.findById(dto.getItemId());



        if(user.isEmpty() || item.isEmpty()){
            throw new EntityNotFoundException("정보가 없습니다.");
        }

        System.out.println("here?3");

        //comment 저장
        Comment comment = new Comment();
        comment.setItemId(item.get().getId());
        comment.setUserId(user.get().getId());
        comment.setContent(dto.getComment());

        commentRepository.save(comment);

    }

}
