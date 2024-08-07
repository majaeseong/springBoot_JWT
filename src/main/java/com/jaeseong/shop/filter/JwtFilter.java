package com.jaeseong.shop.filter;

import com.jaeseong.shop.config.JwtUtil;
import com.jaeseong.shop.domains.CustomUser;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Arrays;


public class JwtFilter extends OncePerRequestFilter {//1회만 하는거
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //요청 들어올때마다 실행할 코드
        Cookie[] cookies = request.getCookies();
        var jwtCookie ="";
        if(cookies == null){
            filterChain.doFilter(request,response);
            return;
        }else{

            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("jwt")) {
                    jwtCookie = cookie.getValue();
                }
            }
        }

        //jwt 체크
        Claims claim;
        try{
            claim=JwtUtil.extractToken(jwtCookie);
        }catch (Exception e){
            filterChain.doFilter(request,response);
            return;
        }

        //auth에 정보 넣기
//        var arr = claim.get("authorities").toString().split(",");
//        var authorities = Arrays.stream(arr).map(a -> new SimpleGrantedAuthority(a)).toList();
        var customUser = new CustomUser(claim.get("username").toString(),"none",null,claim.get("displayName").toString(),(Integer)claim.get("id"));

        var authToken = new UsernamePasswordAuthenticationToken(customUser, "");
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);


        filterChain.doFilter(request,response);


    }

}
