package com.helloIftekhar.springJwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.helloIftekhar.springJwt.service.JwtService;

@RestController
public class DemoController {

    private JwtService jwtService;
    @GetMapping("/demo")
    public ResponseEntity<String> demo() {
        return ResponseEntity.ok("Hello from secured url");
    }

    @GetMapping("/admin_only")
    public ResponseEntity<String> adminOnly() {
        return ResponseEntity.ok("Hello from admin only url");
    }

    @GetMapping("/verifyEmailToken")
public ResponseEntity<String> verifyEmailToken(@RequestParam("token") String token) {

if(!jwtService.isTokenExpired(token)){
    return ResponseEntity.ok("Email verified successfully");
}
return ResponseEntity.badRequest().body("Invalid token or user already verified");

    
}

}
