package com.api.manager.services;


import com.api.manager.data.UserData;
import com.api.manager.models.UserModel;
import com.api.manager.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UserServiceImpl implements UserDetailsService {

    private final UserRepository repository;

    public UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<UserModel> userModelOptional = repository.findByEmail(email);
        if (userModelOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }

        return new UserData(userModelOptional);
    }

}