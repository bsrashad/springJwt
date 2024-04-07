package com.helloIftekhar.springJwt.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.helloIftekhar.springJwt.model.AuthenticationResponse;
import com.helloIftekhar.springJwt.model.EmailRequest;
import com.helloIftekhar.springJwt.model.User;
import com.helloIftekhar.springJwt.repository.UserRepository;
import com.helloIftekhar.springJwt.service.AuthenticationService;
import com.helloIftekhar.springJwt.service.EmailService;
import com.helloIftekhar.springJwt.service.JwtService;

import jakarta.servlet.http.HttpSession;

@RestController
public class DemoController {

    @Autowired
    private UserRepository repository;

    // private final PasswordEncoder passwordEncoder = null;
    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private EmailService emailService;
    @Autowired
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
    System.out.println("+++++++######++++++++");
if(!jwtService.isTokenExpired(token)){
    return ResponseEntity.ok("Email verified successfully");
}
return ResponseEntity.badRequest().body("Invalid token or user already verified");

    
}


// @PostMapping("/forgot-password")
// 	public ResponseEntity<String> forgotPassword(@RequestBody String email) {
//         User user = repository.findByUsername(email).orElseThrow();
//            if(user!=null) {
//             String jwt = jwtService.generateToken(user);

//             String verificationUrl = "http://localhost:8080/generatepassword?token=" + jwt;
//             emailService.sendEmail(email,"forgot password", verificationUrl);
//             return ResponseEntity.status(HttpStatus.OK).body("link sent to your email for reset password");
//         }

//         return ResponseEntity.status(HttpStatus.OK).body("user not exists");

		
// 	}


    @PostMapping("/forgotpassword")
public ResponseEntity<String> forgotPassword(@RequestBody EmailRequest emails) {
    System.out.println("$$$$$$$$$$"+emails.getEmail());
    User user = repository.findByUsername(emails.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + emails.getEmail()));

    
    if (user != null) {
        String jwt = jwtService.generateToken(user);
        String verificationUrl = "http://localhost:8080/generatepassword?token=" + jwt;
        emailService.sendEmail(emails.getEmail(), "forgot password", verificationUrl);
        return ResponseEntity.status(HttpStatus.OK).body("Link sent to your email for reset password");
    }

    return ResponseEntity.status(HttpStatus.OK).body("User not exists");
}

    @GetMapping("/generatepassword")
public ResponseEntity<String> generatePassword(@RequestParam("token") String token) {
    if(!jwtService.isTokenExpired(token)){
        return ResponseEntity.ok("RESET PASSWORD PAGE REDIRECTED successfully");
    } else {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
    }

}

// @GetMapping("/generatepassword")
// public ResponseEntity<String> generatePassword(@RequestParam String token) {
//     if (jwtService.validateToken(token)) {
//         return ResponseEntity.status(HttpStatus.OK).body("redirect:/reset-password");
//     } else {
//         return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
//     }
// }



// @PostMapping("/resetpassword")
// public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> request) {
//     String token = request.get("token");
//     System.out.println("^^^^^^^^^"+token);
//     String newPassword = request.get("newPassword");

//     if(!jwtService.isTokenExpired(token)){

//         String username = jwtService.extractUsername(token);
//         User user = repository.findByUsername(username).orElseThrow();
//         user.setPassword(passwordEncoder.encode(newPassword));
//         user = repository.save(user);

//         return ResponseEntity.ok("RESET PASSWORD successfully");
//     } else {
//         return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
//     }
// }


@GetMapping("/resetpassword")
public ResponseEntity<String> resetPassword(@RequestParam("token") String token) {
    return authenticationService.resetPassword(token);
}



}
