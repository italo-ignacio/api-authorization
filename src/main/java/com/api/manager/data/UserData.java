package com.api.manager.data;

import com.api.manager.models.UserModel;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class UserData implements UserDetails {

    private final Optional<UserModel> userModelOptional;

    public UserData(Optional<UserModel> userModelOptional) {
        this.userModelOptional = userModelOptional;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        return userModelOptional.orElse(new UserModel()).getPassword();
    }

    @Override
    public String getUsername() {
        return userModelOptional.orElse(new UserModel()).getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
