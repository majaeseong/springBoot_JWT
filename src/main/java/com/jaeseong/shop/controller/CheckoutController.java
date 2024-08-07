package com.jaeseong.shop.controller;

import com.jaeseong.shop.domains.Checkout;
import com.jaeseong.shop.domains.CustomUser;
import com.jaeseong.shop.dto.CheckoutDto;
import com.jaeseong.shop.service.CheckoutService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Controller
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
public class CheckoutController {

    private final CheckoutService checkoutService;

    @GetMapping("/checkout")
    public String getCheckout(Authentication auth, Model model){
        List<Checkout> result = checkoutService.getMyCheckout(auth);
        model.addAttribute("checkouts",result);
        return "checkout/list.html";
    }

    @PostMapping("/checkout")
    public String saveCheckout( CheckoutDto dto, Authentication auth, Model model){
        boolean result = checkoutService.saveCheckout(dto,auth);
        if(!result){
            model.addAttribute("error","오류 발생");
        }
        return "redirect:/checkout";
    }

}
