package com.example.oauth2.Service;

import com.example.oauth2.Model.Admin;
import com.example.oauth2.Repository.AdminRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class AdminService {

    @Autowired
    private AdminRepository adminRepository;

    public Map<String,Object> login(OAuth2AuthenticationToken authentication){
        OAuth2User oAuth2User = authentication.getPrincipal();
        OidcUser oidcUser = (OidcUser) oAuth2User;
        String oidcIdTokenValue = oidcUser.getIdToken().getTokenValue();
        Map<String,Object> attributes = oAuth2User.getAttributes();
        Collection<String> authorities = oAuth2User.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        System.out.println(authorities);
        Admin admin = adminRepository.findById((String)attributes.get("sub")).orElse(admin = new Admin((String)attributes.get("sub"),(String)attributes.get("name"),(String)attributes.get("email"),(String)attributes.get("picture"),"USER"));
        Map<String,Object> map = new HashMap<>();
        map.put("message","Admin Logged In");
        map.put("user",admin);
        map.put("IDtoken",oidcIdTokenValue);
        adminRepository.save(admin);
        return map;
    }

    public List<Admin> getAdmin(){
        return adminRepository.findAll();
    }
}
