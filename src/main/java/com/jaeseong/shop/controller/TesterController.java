package com.jaeseong.shop.controller;

import com.jaeseong.shop.domains.CustomUser;
import com.jaeseong.shop.domains.Item;
import com.jaeseong.shop.dto.AddCommentDto;
import com.jaeseong.shop.dto.ItemSearchDto;
import com.jaeseong.shop.service.TesterService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class TesterController {

    private final TesterService service;


    @GetMapping("/list")
    String getItemList(ItemSearchDto dto, Model model){

        Page<Item> items = service.getItems(dto);

        model.addAttribute("items",items);
        model.addAttribute("dto",dto);

        return "item/list.html";
    }

    @GetMapping("/detail/{id}")
    String getItem(@PathVariable int id, Model model) throws Exception {

        Item item = service.getItemById(id);

        model.addAttribute("item",item);
        return "item/detail.html";

    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/write")
    String getAddItem(){
        return "item/write.html";
    }

    @PostMapping("/write")
    @PreAuthorize("isAuthenticated()")
    String postAddItem(@ModelAttribute Item dto, Authentication auth) throws Exception{
        System.out.println(auth);
        service.saveItem(dto,auth.getName());

        return "item/write.html";
    }


    @GetMapping("/update/{id}")
    String getUpdateItem(@PathVariable int id, Model model) throws Exception {
        Item item = service.getItemById(id);
        model.addAttribute("item",item);

        return "item/update.html";
    }

    @PostMapping("/update")
    String patchUpdateItem(@ModelAttribute Item dto) throws Exception{

        service.updateItem(dto);

        return "redirect:/detail/"+dto.getId();
    }

    @PostMapping("/delete/{id}")
    ResponseEntity<String> deleteItem(@PathVariable int id) {
        service.deleteById(id);

        return ResponseEntity.status(200).body("ok");
    }



    @PostMapping("/comment")
    @PreAuthorize("isAuthenticated()")
    ResponseEntity<String> postComment(@RequestBody AddCommentDto dto, Authentication auth) throws Exception{

        service.saveComment(dto,auth);

        return ResponseEntity.status(200).body("ok");
    }


}
