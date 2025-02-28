package com.clinicmanagement.clinic.config;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.Entities.UserRole;
import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.dto.user.UserRequest;
import com.clinicmanagement.clinic.exception.AppException;
import com.clinicmanagement.clinic.exception.ErrorCode;
import com.clinicmanagement.clinic.repository.UserRepository;
import com.clinicmanagement.clinic.service.CustomUserDetailsService;
import com.clinicmanagement.clinic.service.PatientService;
import com.clinicmanagement.clinic.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
//import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
//import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


import org.springframework.security.web.SecurityFilterChain;

import java.time.LocalDate;
import java.util.*;

//
@EnableWebSecurity
@EnableMethodSecurity
@AllArgsConstructor
@Configuration
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private CustomOAuth2AuthenticationSuccessHandler successHandler;

    private final String[] PUBLIC_ENDPOINT = {"verifytoken", "/resetPass", "/forgotpassword", "/", "/login", "/js/**", "/images/**", "/css/**", "/fonts/**", "/register", "/check-appointment", "/about"};

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(request ->
                        request.requestMatchers(PUBLIC_ENDPOINT).permitAll()
                                .requestMatchers("/images/**", "/css/**", "/js/**", "/fonts/**").permitAll()
                                .requestMatchers("/admin/**").hasAuthority("ADMIN")
                                .requestMatchers("/**").hasAnyAuthority("DOCTOR", "USER")
                                .requestMatchers("/doctor/**").hasAuthority("DOCTOR")
                                .requestMatchers("/myInfo").authenticated()
                                .anyRequest().authenticated()
                )
                .formLogin(form ->
                        form
                                .loginPage("/login")
                                .loginProcessingUrl("/login")
                                .usernameParameter("username")
                                .passwordParameter("password")
                                .successHandler((request, response, authentication) -> {
                                    String role = authentication.getAuthorities().stream()
                                            .map(GrantedAuthority::getAuthority)
                                            .findFirst()
                                            .orElse("");
                                    switch (role) {
                                        case "ADMIN" -> response.sendRedirect("/admin");
                                        case "USER" -> response.sendRedirect("/");
                                        case "DOCTOR" -> response.sendRedirect("/doctor");
                                        default -> response.sendRedirect("/login?error=true");
                                    }
                                })
                                .failureUrl("/login?error=true")
                )
                .oauth2Login(oauth2 ->
                        oauth2.loginPage("/login") // Redirect về login form của bạn sau xác thực Google OAuth2
                                .userInfoEndpoint(userInfo ->
                                        userInfo.userService(customOAuth2UserService) // Logic xử lý thông tin người dùng sau xác thực
                                )
                                .successHandler(successHandler)
                )
                .logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/"))

        ;
        httpSecurity.csrf(AbstractHttpConfigurer::disable);
        return httpSecurity.build();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10);
    }

}



