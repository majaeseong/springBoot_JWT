package com.jaeseong.shop.service;

import com.jaeseong.shop.domains.CustomUser;
import com.jaeseong.shop.domains.Member;
import com.jaeseong.shop.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Autowired
    public MyUserDetailsService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //passwordEncoder 에서 자동으로 해시해서 체크해준다고 함. -> 비번만 뭔지 찾아주면 됨.
        //여기서 세션 데이터 내려줌.
        Optional<Member> existUser = memberRepository.findByUsername(username);
        if(existUser.isEmpty()){
            throw new UsernameNotFoundException("userId is not exist");
        }

        Member user = existUser.get();
        List<GrantedAuthority> auth = new ArrayList<>();
        auth.add(new SimpleGrantedAuthority("1"));
//        auth.add(new SimpleGrantedAuthority("2"));
        return new CustomUser(user.getUsername(), user.getPassword(), auth, user.getDisplayName(), user.getId());


    }
}

