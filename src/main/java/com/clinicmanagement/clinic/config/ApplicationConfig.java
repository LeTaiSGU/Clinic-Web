package com.clinicmanagement.clinic.config;

import com.clinicmanagement.clinic.Entities.Role;
import com.clinicmanagement.clinic.Entities.UserRole;
import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.repository.RoleRepository;
import com.clinicmanagement.clinic.repository.UserRepository;
import com.clinicmanagement.clinic.repository.UserRoleRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;

@Configuration
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
@Slf4j
@EnableAsync
public class ApplicationConfig {

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserRoleRepository userRoleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Bean
    ApplicationRunner applicationRunner(UserRepository userRepository){
        return args -> {
            if (roleRepository.findByRoleName("ADMIN") == null) {
                roleRepository.save(Role.builder()
                        .roleName("ADMIN")
                        .build());
                log.info("Role ADMIN has been added to the database.");
            }
            if (roleRepository.findByRoleName("USER") == null) {
                roleRepository.save(Role.builder()

                        .roleName("USER")
                        .build());
                log.info("Role USER has been added to the database.");
            }
            if (roleRepository.findByRoleName("DOCTOR") == null) {
                roleRepository.save(Role.builder()
                        .roleName("DOCTOR")
                        .build());
                log.info("Role DOCTOR has been added to the database.");
            }

            if(userRepository.findByUsername("admin").isEmpty()){
                Role adminRole = roleRepository.findByRoleName("ADMIN");
                Useraccount user = Useraccount.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin1234"))
                        .status(true)
                        .build();
                UserRole userRole = new UserRole();
                userRole.setUser(user);
                userRole.setRole(adminRole);
                user.setUserRoles(new HashSet<>());
                user.getUserRoles().add(userRole);
                userRepository.save(user);
                userRoleRepository.save(userRole);
                log.warn("Admin account has been created with the default password: admin1234, please change your admin password.");
            }
        };
    }

}
