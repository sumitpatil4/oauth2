package com.example.oauth2.Controller;

import com.example.oauth2.Jwt.JwtTokenUtil;
import com.example.oauth2.Model.Admin;
import com.example.oauth2.Service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.security.Principal;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class AdminController {

    @Autowired
    private AdminService adminService;

    @Autowired
    private JwtTokenUtil jwtUtil;

    @GetMapping("/register")
    public ResponseEntity<Object> register(@RequestHeader("Authorization") String token){
        Base64.Decoder decoder = Base64.getUrlDecoder();
        System.out.println(token);
        String[] chunks = token.split("\\.");
        String payload = new String(decoder.decode(chunks[1]));
        System.out.println(payload);
        return new ResponseEntity<>(payload,HttpStatus.OK);
    }

    @GetMapping("/auth/login")
    public ResponseEntity<?> login(OAuth2AuthenticationToken authentication){
        System.out.println("LOGGING IN!!");
        System.out.println(authentication);
        System.out.println(authentication);
        Map<String,Object> map = adminService.login(authentication);
        Admin admin = (Admin) map.get("user");
        String accessToken = jwtUtil.generateAccessToken(admin);
        map.put("accessToken",accessToken);
        return new ResponseEntity<>(map,HttpStatus.OK);
    }

    @GetMapping("/getUsers")
    public List<Admin> getAdmin(){
        return adminService.getAdmin();
    }

    @GetMapping("/displayUser")
    public Principal getUser(Principal principal){
        return principal;
    }

    @GetMapping("/user")
//    @RolesAllowed("USER")
    @PreAuthorize("hasRole('USER')")
    public String user(){
        return "I am USER";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
//    @PreAuthorize("hasRole('ADMIN')")
    public String admin(){
        return "I am ADMIN";
    }

    @GetMapping("/leadership")
    public String leader(){
        return "I am LEADER";
    }

    @GetMapping("/auth/hello")
    public ResponseEntity hello(){
        Map<String,Object> mp = new HashMap<>();
        mp.put("message","Hello");
        return new ResponseEntity(mp,HttpStatus.OK);
    }

}
