package com.rashad.springJwt.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.rashad.springJwt.model.AuthenticationResponse;
import com.rashad.springJwt.model.Token;
import com.rashad.springJwt.model.User;
import com.rashad.springJwt.repository.TokenRepository;
import com.rashad.springJwt.repository.UserRepository;

@Service
public class AuthenticationService {

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private EmailService emailService;

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final TokenRepository tokenRepository;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository,
                                 PasswordEncoder passwordEncoder,
                                 JwtService jwtService,
                                 TokenRepository tokenRepository,
                                 AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(User request) {

        // check if user already exist. if exist than authenticate the user
        if(repository.findByUsername(request.getUsername()).isPresent()) {
            return new AuthenticationResponse(null, "User already exist");
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));


        user.setRole(request.getRole());
        user.setIsVerified(false);
        user.setBusinessUnit(request.getBusinessUnit());

        user = repository.save(user);

        String jwt = jwtService.generateToken(user);

        saveUserToken(jwt, user);
        String verificationUrl = "http://localhost:8080/verifyEmailToken?token=" + jwt;

        emailService.sendEmail(request.getUsername(),"email verification", verificationUrl);
        System.out.println("-------------------"+verificationUrl);

        return new AuthenticationResponse(jwt, "User registration was successful");

    }

    // public void sendVerificationEmail(String email, String token) {
    //     String verificationUrl = "http://localhost:8080/verifyEmailToken?token=" + token;
    
    //     SimpleMailMessage message = new SimpleMailMessage();
    //     message.setTo(email);
    //     message.setSubject("Email Verification");
    //     message.setText("Click the link below to verify your email:\n" + verificationUrl);
    
    //     javaMailSender.send(message);
    // }


    public ResponseEntity<Map<String, String>> authenticate(User request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = repository.findByUsername(request.getUsername()).orElseThrow();
    if (!user.getIsVerified()) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Email is not verified yet");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
        String jwt = jwtService.generateToken(user);

        revokeAllTokenByUser(user);
        saveUserToken(jwt, user);
        Map<String, String> response = new HashMap<>();
        response.put("jwt", jwt);
        // response.put("message", "User login was successful");

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }
    private void revokeAllTokenByUser(User user) {
        List<Token> validTokens = tokenRepository.findAllTokensByUser(user.getId());
        if(validTokens.isEmpty()) {
            return;
        }

        validTokens.forEach(t-> {
            t.setLoggedOut(true);
        });

        tokenRepository.saveAll(validTokens);
    }
    private void saveUserToken(String jwt, User user) {
        Token token = new Token();
        token.setToken(jwt);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    
public ResponseEntity<String> resetPassword( String token,String newPassword) {
    

    if(!jwtService.isTokenExpired(token)){

        String username = jwtService.extractUsername(token);
        User user = repository.findByUsername(username).orElseThrow();
        user.setPassword(passwordEncoder.encode(newPassword));
        // user.setPassword(newPassword);
        user = repository.save(user);

        return ResponseEntity.ok("RESET PASSWORD successfully");
    } else {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
    }
}

public ResponseEntity<String> changePassword( String email, String oldPassword,String newPassword) {
    // String oldpasswordencoded= passwordEncoder.encode(oldPassword);
    // Optional<User> userOptional = repository.findByUsernameAndPassword(email, passwordEncoder.matches(newPassword, oldPassword)  oldPassword);
    Optional<User> userOptional = repository.findByUsername(email);
    if (userOptional.isPresent()) {
        User user = userOptional.get();
        if(passwordEncoder.matches(oldPassword, user.getPassword())){
            String encodednewpassword=passwordEncoder.encode(newPassword);
            user.setPassword(encodednewpassword);
        repository.save(user);
        return ResponseEntity.status(HttpStatus.OK).body("Password changed successfully for " + email);
        }else{
            return ResponseEntity.status(HttpStatus.OK).body("password doesnt match");
        }
        
        
    } else {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid email ");
    }
}


}
