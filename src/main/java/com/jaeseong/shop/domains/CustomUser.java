package com.jaeseong.shop.domains;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class CustomUser extends User {

    private final Integer id;
    private final String displayName;

    public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String displayName, Integer id) {
        super(username, password, authorities);
        this.id = id;
        this.displayName =displayName;

    }

}