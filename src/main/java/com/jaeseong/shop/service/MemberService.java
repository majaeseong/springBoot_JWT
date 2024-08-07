package com.jaeseong.shop.service;

import com.jaeseong.shop.config.JwtUtil;
import com.jaeseong.shop.domains.Member;
import com.jaeseong.shop.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public List<Member> getAllMembers(){
        return memberRepository.findAll();
    }

    public void addMember(Member member) throws Exception {

        boolean existUser = memberRepository.existsByUsername(member.getUsername());

        if(existUser){
            throw new Exception("중복");
        }

        var encodedPassword = passwordEncoder.encode(member.getPassword());
        member.setPassword(encodedPassword);

        memberRepository.save(member);

    }

    public String loginJwt(Map<String,String> data){

        var authToken = new UsernamePasswordAuthenticationToken(data.get("username"), data.get("password"));
        //로그인 체크 -> loadUserBy~~
        var auth = authenticationManagerBuilder.getObject().authenticate(authToken);
        //Authenticiation auth 를 대신하기 위해 SecurityContextHolder.getContext() 이거 쓸 수 있게 해줌.
        SecurityContextHolder.getContext().setAuthentication(auth);

        //jwt 발급
        var jwt = JwtUtil.createToken(SecurityContextHolder.getContext().getAuthentication());
        System.out.println(jwt);



        return jwt;
    }

}
