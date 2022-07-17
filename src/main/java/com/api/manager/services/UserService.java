package com.api.manager.services;

import com.api.manager.models.UserModel;
import com.api.manager.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;


@Service
public class UserService {

    @Autowired
    UserRepository userRepository;

    @Transactional
    public UserModel save(UserModel userModel) {return userRepository.save(userModel);}

    public List<UserModel> findAll() {return userRepository.findAll();}

    public Optional<UserModel> findById(Long id) {return userRepository.findById(id);}

    public Optional<UserModel> findByEmail(String email) {return userRepository.findByEmail(email);}

    @Transactional
    public void delete(UserModel userModel) {
        userRepository.delete(userModel);
    }
}
