package com.api.manager.controllers;

import com.api.manager.dtos.LoginDto;
import com.api.manager.dtos.UserDto;
import com.api.manager.models.UserModel;
import com.api.manager.services.UserService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDateTime;
import java.util.*;


@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping("/users")
public class UserController {
    public static final String PREFIX = "Bearer ";
    @Autowired
    UserService userService;


    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    private String validateToken(String token){
        Dotenv dotenv = Dotenv.load();
        String email = JWT.require(Algorithm.HMAC512(dotenv.get("TOKEN_SECRET")))
                .build()
                .verify(token)
                .getSubject();
        return email;
    }
    @PostMapping
    public ResponseEntity<Object> saveUser(@RequestBody @Valid UserDto userDto){
        Map<String, String> response = new HashMap<>();
        var userModel = new UserModel();
        boolean verify = false;
        if(userDto.getName()!=null){userModel.setName(userDto.getName());}else {
            response.put("name", "name field is required");
            verify = true;
        }
        if(userDto.getEmail()!=null){ userModel.setEmail(userDto.getEmail());}else {
            response.put("email", "email field is required");
            verify = true;
        }
        if(userDto.getPassword()!=null){userModel.setPassword(bCryptPasswordEncoder.encode(userDto.getPassword()));}else {
            response.put("password", "password field is required");
            verify = true;
        }
        if(verify){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        userModel.setCreatedAt(LocalDateTime.now());
        userModel.setUpdatedAt(LocalDateTime.now());
        userModel.setIs_admin(false);

        try{
            userService.save(userModel);
            response.put("message", "User created successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        }catch (Exception e){
            String error = e.getCause().getCause().getMessage();
            response.put("ERROR", "TRUE");
            if(error.contains("Duplicate entry")){
                response.put("message", "E-mail already exists");
            }else {
                response.put("message", "Could not created user");
                response.put("err",error);
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @GetMapping
    public ResponseEntity<List<UserModel>> getAllUsers(){
        return ResponseEntity.status(HttpStatus.OK).body(userService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Object> getByIdUser(@PathVariable(value = "id") Long id){
        Map<String, String> response = new HashMap<>();
        Optional<UserModel> userModelOptional = userService.findById(id);
        if(!userModelOptional.isPresent()){
            response.put("ERROR", "TRUE");
            response.put("message", "User not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(userModelOptional.get());
    }


    @DeleteMapping("/{id}")
    public ResponseEntity<Object> deleteUser(@PathVariable(value = "id")Long id,@RequestHeader String Authorization){
        Map<String, String> response = new HashMap<>();
        String token = Authorization.replace(PREFIX,"");
        try{
            String email = validateToken(token);
            if(email == null){
                response.put("ERROR","True");
                response.put("message","Login required/Invalid token");
                response.put("Authorization","Bearer token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<UserModel> userModelOptionalEmail = userService.findByEmail(email);
            if(!userModelOptionalEmail.isPresent()){
                response.put("ERROR","True");
                response.put("message","Invalid token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            Optional<UserModel> userModelOptional = userService.findById(id);
            if(!userModelOptional.isPresent()){
                response.put("ERROR", "TRUE");
                response.put("message", "User not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }

            if(userModelOptionalEmail.get().getIs_admin() || userModelOptionalEmail.get().getId() == userModelOptional.get().getId()){
                try{
                    userService.delete(userModelOptional.get());
                    response.put("message", "User successfully deleted");
                    return ResponseEntity.status(HttpStatus.OK).body(response);
                }catch (Exception e){
                    response.put("ERROR", "TRUE");
                    response.put("message", "Could not delete user");
                    response.put("err", e.getCause().getLocalizedMessage());
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }
            }
            response.put("ERROR","True");
            response.put("message","UNAUTHORIZED");
            response.put("Owner/Admin","Only the owner or admin can delete a user");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }catch (Exception e){
            response.put("ERROR","True");
            response.put("message","Login required/Invalid token");
            response.put("Authorization","Bearer token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }



    }

    @PutMapping("/{id}")
    public ResponseEntity<Object> updateUser(@PathVariable(value = "id")Long id,@RequestBody @Valid UserDto userDto,@RequestHeader String Authorization){

        Map<String, String> response = new HashMap<>();
        String token = Authorization.replace(PREFIX,"");
        try{
            String email = validateToken(token);
            if(email == null){
                response.put("ERROR","True");
                response.put("message","Login required/Invalid token");
                response.put("Authorization","Bearer token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<UserModel> userModelOptionalEmail = userService.findByEmail(email);
            if(!userModelOptionalEmail.isPresent()){
                response.put("ERROR","True");
                response.put("message","Invalid token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            Optional<UserModel> userModelOptional = userService.findById(id);
            if(!userModelOptional.isPresent()){
                response.put("ERROR", "TRUE");
                response.put("message", "User not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }

            if(userModelOptionalEmail.get().getIs_admin() || userModelOptionalEmail.get().getId() == id){
                int sum = 0;
                var userModel = userModelOptional.get();
                if(userDto.getName()!=null){ userModel.setName(userDto.getName());}else {sum++;}
                if(userDto.getEmail()!=null){ userModel.setEmail(userDto.getEmail());}else {sum++;}
                if(userDto.getPassword()!=null){userModel.setPassword(bCryptPasswordEncoder.encode(userDto.getPassword()));}else {sum++;}
                if(sum ==3){
                    response.put("message","Possible fields to update: (name, email, password)");
                    return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
                }
                userModel.setUpdatedAt(LocalDateTime.now());
                try{
                    userService.save(userModel);
                    response.put("message", "User updated successfully");
                    return ResponseEntity.status(HttpStatus.OK).body(response);
                }catch (Exception e){
                    String error = e.getCause().getCause().getMessage();
                    response.put("ERROR", "TRUE");
                    if(error.contains("Duplicate entry")){
                        response.put("message", "E-mail already exists");
                    }else {
                        response.put("message", "Could not update user");
                        response.put("err", error);
                    }
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }
            }
            response.put("ERROR","True");
            response.put("message","UNAUTHORIZED");
            response.put("Owner/Admin","Only the owner or admin can update a user");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }catch (Exception e){
            response.put("ERROR","True");
            response.put("message","Login required/Invalid token");
            response.put("Authorization","Bearer token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
    @PostMapping("/validatePassword")
    public ResponseEntity<Object> validatePasswordUser(@RequestBody @Valid LoginDto loginDto) {
        Optional<UserModel> userModelOptional = userService.findByEmail(loginDto.getEmail());
        if (userModelOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }

        var user = userModelOptional.get();
        boolean valid = bCryptPasswordEncoder.matches(loginDto.getPassword(), user.getPassword());

        HttpStatus status = (valid) ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;
        return ResponseEntity.status(status).body(valid);
    }

}
/*

 Map<String, String> response = new HashMap<>();
        Optional<UserModel> userModelOptional = userService.findByEmail(loginDto.getEmail());

        if (userModelOptional.isEmpty()) {
            response.put("ERROR", "TRUE");
            response.put("message", "User not found");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        Dotenv dotenv = Dotenv.load();
        var user = userModelOptional.get();
        boolean valid = bCryptPasswordEncoder.matches(loginDto.getPassword(), user.getPassword());
        if(valid){
            String token = JWT.create().withSubject(user.getEmail()).
                    withExpiresAt(new Date(System.currentTimeMillis() + Integer.parseInt(dotenv.get("TOKEN_EXPIRATION")))).
                    sign(Algorithm.HMAC512(dotenv.get("TOKEN_SECRET")));

            response.put("message", "Successfully logged in");
            response.put("token", token);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }else{
            response.put("ERROR", "TRUE");
            response.put("message","Invalid password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

 */
