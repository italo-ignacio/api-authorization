package com.api.manager.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class ValidationHandler extends ResponseEntityExceptionHandler{

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        errors.put("Error","True");
        ex.getBindingResult().getAllErrors().forEach((error) ->{

            String fieldName = ((FieldError) error).getField();
            String message = error.getDefaultMessage();
            errors.put(fieldName, message);
        });

        return new ResponseEntity<Object>(errors, HttpStatus.BAD_REQUEST);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
                                                                  HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        String error = ex.getCause().getLocalizedMessage();
        if(error.contains("3 known properties:")){
            errors.put("Error","True");
            errors.put("Type","Unrecognized field");
            errors.put("message","Possible fields: (name, email, password)");
        } else if (error.contains("6 known properties:")) {
            errors.put("Error","True");
            errors.put("Type","Unrecognized field");
            errors.put("message","Possible fields: (name, cod, note, details, url)");
        }else{
            errors.put("Error","True");
            errors.put("message",ex.getCause().getLocalizedMessage());
        }

        return new ResponseEntity<Object>(errors, HttpStatus.BAD_REQUEST);
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException ex,
                                                                          HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        errors.put("Error","True");
        errors.put("message","Login required/Invalid token");
        errors.put("Authorization","Bearer token");

        return new ResponseEntity<Object>(errors, HttpStatus.UNAUTHORIZED);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex,
                                                        HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        errors.put("Error","True");
        errors.put("message","ID must be of type Long");
        return new ResponseEntity<Object>(errors, HttpStatus.BAD_REQUEST);
    }

}