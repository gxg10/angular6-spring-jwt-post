package com.spring.security.spring.controller;

import com.spring.security.spring.message.request.LoginForm;
import com.spring.security.spring.message.request.SignupForm;
import com.spring.security.spring.message.response.JwtResponse;
import com.spring.security.spring.message.response.ResponseMessage;
import com.spring.security.spring.model.Role;
import com.spring.security.spring.model.RoleName;
import com.spring.security.spring.model.User;
import com.spring.security.spring.repository.RoleRepository;
import com.spring.security.spring.repository.UserRepository;
import com.spring.security.spring.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                        loginRequest.getPassword())
        );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(),
                userDetails.getAuthorities()));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupForm signupRequest) {
        if(userRepository.existsByUsername(signupRequest.getUsername())) {
            return new ResponseEntity<>(new ResponseMessage("Fail -> " +
                    "username is already taken"), HttpStatus.BAD_REQUEST);

        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("fail -> " +
                    "email already in use"), HttpStatus.BAD_REQUEST);
        }

        User user = new User(signupRequest.getName(), signupRequest.getUsername(),
                signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
            switch (role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                            .orElseThrow(()-> new RuntimeException("fail->" +
                                    "user role cannot find"));
                    roles.add(adminRole);

                    break;
                case "pm":
                    Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
                            .orElseThrow(()-> new RuntimeException("fail " +
                                    "user role cannot find"));
                    roles.add(pmRole);

                    break;

                default:
                    Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                            .orElseThrow(()-> new RuntimeException("fail " +
                                    "user role cannot find"));
                    roles.add(userRole);
            }
        });

        user.setRoles(roles);
        userRepository.save(user);

        return new ResponseEntity<>(new ResponseMessage("user registered succes" +
                "fully"), HttpStatus.OK);
    }
}
