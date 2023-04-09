package com.example.oauth2.Repository;

import com.example.oauth2.Model.Admin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<Admin,String>{

    Optional<Admin> findByEmail(String email);
}
