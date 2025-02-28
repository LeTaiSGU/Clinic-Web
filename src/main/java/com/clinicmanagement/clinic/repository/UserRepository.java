package com.clinicmanagement.clinic.repository;

import com.clinicmanagement.clinic.Entities.Useraccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Useraccount, Integer> {
    boolean existsByUsername(String username);
    Optional<Useraccount> findByUsername(String username);
    Useraccount findByPatient_Email(String email);
    Optional<Useraccount> findByResetPasswordToken(String token);
}
