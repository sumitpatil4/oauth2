package com.example.oauth2.Config;

import com.example.oauth2.Jwt.JwtTokenFilter;
import com.example.oauth2.Repository.AdminRepository;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableGlobalMethodSecurity(
        prePostEnabled = true, securedEnabled = false, jsr250Enabled = true
)
public class ApplicationSecurity {

    @Autowired private AdminRepository adminRepo;
    @Autowired private JwtTokenFilter jwtTokenFilter;

//    @Bean
//    public UserDetailsService userDetailsService() {
//        return new UserDetailsService() {
//
//            @Override
//            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//                return adminRepo.findByEmail(username)
//                        .orElseThrow(
//                                () -> new UsernameNotFoundException("User " + username + " not found"));
//            }
//        };
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(
//            AuthenticationConfiguration authConfig) throws Exception {
//        return authConfig.getAuthenticationManager();
//    }
    @Bean
    @Order(1)
    public SecurityFilterChain configure1(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http
                .cors().configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        System.out.println(request.getRequestURL());
                        return null;
                    }
                }).and()
                .requestMatchers().antMatchers("/auth/login/**","/oauth2/authorization/google/**","/login/oauth2/code/google/**")
                .and()
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .oauth2Login();

        return http.build();
    }
//
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.
                authorizeRequests().anyRequest().permitAll().
                and().
                sessionManagement().
                sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(
                        (request, response, ex) -> {
                            response.sendError(
                                    HttpServletResponse.SC_UNAUTHORIZED,
                                    ex.getMessage()
                            );
                        }
                );
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
