package com.api.manager.controllers;

import com.api.manager.dtos.PatrimonyDto;
import com.api.manager.models.PatrimonyModel;
import com.api.manager.models.UserModel;
import com.api.manager.services.PatrimonyService;
import com.api.manager.services.UserService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping("/patrimonies")
public class PatrimonyController {

    public static final String PREFIX = "Bearer ";
    @Autowired
    PatrimonyService patrimonyService;

    @Autowired
    UserService userService;

    private String validateToken(String token){
        Dotenv dotenv = Dotenv.load();
        String email = JWT.require(Algorithm.HMAC512(dotenv.get("TOKEN_SECRET")))
                .build()
                .verify(token)
                .getSubject();
        return email;
    }
    @PostMapping
    public ResponseEntity<Object> savePatrimony(@RequestBody @Valid PatrimonyDto patrimonyDto,@RequestHeader String Authorization){
        Map<String, String> response = new HashMap<>();
        String token = Authorization.replace(PREFIX,"");
        if(patrimonyDto.getName() == null || patrimonyDto.getCod() == null){
            response.put("ERROR", "TRUE");
            response.put("message","Fields (name, cod) are required");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        try{
            String email = validateToken(token);
            if(email == null){
                response.put("ERROR","True");
                response.put("message","Login required/Invalid token");
                response.put("Authorization","Bearer token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<UserModel> userModelOptional = userService.findByEmail(email);
            if(!userModelOptional.isPresent()){
                response.put("ERROR","True");
                response.put("message","Invalid token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            var patrimonyModel = new PatrimonyModel();
            BeanUtils.copyProperties(patrimonyDto,patrimonyModel);
            patrimonyModel.setUser(userModelOptional.get());
            patrimonyModel.setCreatedAt(LocalDateTime.now());
            patrimonyModel.setUpdatedAt(LocalDateTime.now());
            try{
                patrimonyService.save(patrimonyModel);
                response.put("message", "Patrimony created successfully");
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            }catch (Exception e){
                String error = e.getCause().getCause().getMessage();
                response.put("ERROR", "TRUE");
                if(error.contains("Duplicate entry")){
                    response.put("message", "Code already exists");
                }else {
                    response.put("message", "Could not created patrimony");
                    response.put("err",error);
                }
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }
        }catch (Exception e){
            response.put("ERROR","True");
            response.put("message","Login required/Invalid token");
            response.put("Authorization","Bearer token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @GetMapping
    public ResponseEntity<Iterable<PatrimonyModel>> getAllPatrimonies(){
        return ResponseEntity.status(HttpStatus.OK).body(patrimonyService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Object> getByIdPatrimony(@PathVariable(value = "id")Long id){
        Map<String, String> response = new HashMap<>();
        Optional<PatrimonyModel> patrimonyModelOptional = patrimonyService.findById(id);
        if(!patrimonyModelOptional.isPresent()){
            response.put("ERROR","True");
            response.put("message","Patrimony not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(patrimonyModelOptional.get());
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Object> deletePatrimony(@PathVariable(value = "id")Long id,@RequestHeader String Authorization){
        Map<String, String> response = new HashMap<>();
        String token = Authorization.replace(PREFIX,"");
        try{
            String email = validateToken(token);
            if(email==null){
                response.put("ERROR","True");
                response.put("message","Login required/Invalid token");
                response.put("Authorization","Bearer token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<UserModel> userModelOptional = userService.findByEmail(email);
            if(!userModelOptional.isPresent()){
                response.put("ERROR","True");
                response.put("message","Invalid token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<PatrimonyModel> patrimonyModelOptional = patrimonyService.findById(id);
            if(!patrimonyModelOptional.isPresent()){
                response.put("ERROR","True");
                response.put("message","Patrimony not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
            if(patrimonyModelOptional.get().getIdOwner() == userModelOptional.get().getId() || userModelOptional.get().getIs_admin()){
                try{
                    patrimonyService.delete(patrimonyModelOptional.get());
                    response.put("message","Patrimony deleted successfully");
                    return ResponseEntity.status(HttpStatus.OK).body(response);
                }catch (Exception e){
                    response.put("ERROR","True");
                    response.put("message","Could not delete patrimony");
                    response.put("err",e.getCause().getLocalizedMessage());
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }
            }
            response.put("ERROR","True");
            response.put("message","UNAUTHORIZED");
            response.put("Owner/Admin","Only the owner or admin can delete the patrimony");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }catch (Exception e){
            response.put("ERROR","True");
            response.put("message","Login required/Invalid token");
            response.put("Authorization","Bearer token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<Object> updatePatrimony(@PathVariable(value = "id")Long id,@RequestBody PatrimonyDto patrimonyDto,@RequestHeader String Authorization){
        Map<String, String> response = new HashMap<>();
        String token = Authorization.replace(PREFIX,"");
        try{
            String email = validateToken(token);
            if(email==null){
                response.put("ERROR","True");
                response.put("message","Login required/Invalid token");
                response.put("Authorization","Bearer token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<UserModel> userModelOptional = userService.findByEmail(email);
            if(!userModelOptional.isPresent()){
                response.put("ERROR","True");
                response.put("message","Invalid token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            Optional<PatrimonyModel> patrimonyModelOptional = patrimonyService.findById(id);
            if(!patrimonyModelOptional.isPresent()){
                response.put("ERROR","True");
                response.put("message","Patrimony not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
            if(patrimonyModelOptional.get().getIdOwner() == userModelOptional.get().getId() || userModelOptional.get().getIs_admin()){
                var patrimonyModel = patrimonyModelOptional.get();
                int sum = 0;
                if(patrimonyDto.getName() != null){patrimonyModel.setName(patrimonyDto.getName());}else{sum++;}
                if(patrimonyDto.getCod() != null){patrimonyModel.setCod(patrimonyDto.getCod());}else{sum++;}
                if(patrimonyDto.getNote() != null){patrimonyModel.setNote(patrimonyDto.getNote());}else{sum++;}
                if(patrimonyDto.getDetails() != null){patrimonyModel.setDetails(patrimonyDto.getDetails());}else{sum++;}
                if(patrimonyDto.getUrl() != null){patrimonyModel.setUrl(patrimonyDto.getUrl());}else{sum++;}
                if(patrimonyDto.getUser() != null){patrimonyModel.setUser(patrimonyDto.getUser());}else{sum++;}
                if(sum == 6){
                    response.put("message","Possible fields to update: (name, cod, note, details, url, user)");
                    return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
                }

                patrimonyModel.setUpdatedAt(LocalDateTime.now());
                try{
                    patrimonyService.save(patrimonyModel);
                    response.put("message","Patrimony update successfully");
                    return ResponseEntity.status(HttpStatus.OK).body(response);
                }catch (Exception e){
                    String error = e.getCause().getCause().getMessage();
                    response.put("ERROR", "TRUE");
                    if(error.contains("Duplicate entry")){
                        response.put("message", "Code already exists");
                    }else {
                        response.put("message", "Could not update user");
                        response.put("err", error);
                    }
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }
            }
            response.put("ERROR","True");
            response.put("message","UNAUTHORIZED");
            response.put("Owner/Admin","Only the owner or admin can update a patrimony");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);

        }catch (Exception e){
            response.put("ERROR","True");
            response.put("message","Login required/Invalid token");
            response.put("Authorization","Bearer token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
}
