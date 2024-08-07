package com.jaeseong.shop.service;

import com.jaeseong.shop.domains.Checkout;
import com.jaeseong.shop.domains.CustomUser;
import com.jaeseong.shop.dto.CheckoutDto;
import com.jaeseong.shop.repository.CheckoutRepository;
import com.jaeseong.shop.repository.MemberRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CheckoutService {

    private final CheckoutRepository checkoutRepository;
    private final MemberRepository memberRepository;

    public List<Checkout> getMyCheckout(Authentication auth){
        CustomUser customUser = (CustomUser) auth.getPrincipal();

        var user = memberRepository.findById(customUser.getId());

        if(user.isEmpty() ){
            throw new EntityNotFoundException("정보가 없습니다.");
        }

        return user.get().getCheckouts();
//        return checkoutRepository.customFindAll();
//        return checkoutRepository.findAllByUserId(user.get().getId());
    }

    public boolean saveCheckout(CheckoutDto dto, Authentication auth){
        try{
            CustomUser customUser = (CustomUser) auth.getPrincipal();

            var user = memberRepository.findById(customUser.getId());

            if(user.isEmpty() ){
                throw new EntityNotFoundException("정보가 없습니다.");
            }

            Checkout newCheckout = new Checkout();
            newCheckout.setUser(user.get());
            newCheckout.setPrice(dto.getPrice());
            newCheckout.setQuantity(dto.getQuantity());
            newCheckout.setItemName(dto.getItemName());

            checkoutRepository.save(newCheckout);

            return true;
        }catch(Exception e){
            System.out.println(e.getMessage());
            return false;
        }

    }

}
