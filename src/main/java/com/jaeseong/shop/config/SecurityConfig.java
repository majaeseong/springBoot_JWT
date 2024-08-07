package com.jaeseong.shop.config;

import com.jaeseong.shop.filter.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public CsrfTokenRepository csrfTokenRepository(){
        HttpSessionCsrfTokenRepository repo = new HttpSessionCsrfTokenRepository();
        repo.setHeaderName("X-XSRF-TOKEN");

        // URL 파라미터에서 토큰에 대응되는 변수 설정
        repo.setParameterName("_csrf");
        // 세션에서 토큰을 인덱싱 하는 문자열을 설정. 기본값이 무척 길어서 오버라이딩 하는 게 좋아요.
        // 기본값: "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN"
        repo.setSessionAttributeName("CSRF_TOKEN");
        return repo;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

//        http.csrf(
//                csrf -> csrf.csrfTokenRepository(csrfTokenRepository())
//                        .ignoringRequestMatchers("/login")  //csrf 보안 끌 페이지
//        );
        http.csrf((csrf)->csrf.disable());  //다른 사이트에서 API 요청 허용하는거. (개발시에만 하셈)

        http.authorizeHttpRequests((auth)->{
            auth.requestMatchers("/**").permitAll();
        });

        //form Login
//        http.formLogin((form)->
//                form.loginPage("/login")    //로그인 페이지
//                    .defaultSuccessUrl("/list") //성공 시 이동
////                    .failureUrl("/fail")    //실패 시 이동 URL -> 안적으면 /login?error 로 이동
//        );

        //jwt를 위해 session 생성하지 말라는 뜻
        http.sessionManagement((session)->session.sessionCreationPolicy((SessionCreationPolicy.STATELESS)));

        http.addFilterBefore(new JwtFilter(), ExceptionTranslationFilter.class);


        http.logout(logout -> logout.logoutUrl("/logout"));

        return http.build();
    }

}

/*
    1. 로그인 페이지
    2. 폼으로 로그인
    3. 유저 정보 꺼내기


 */