package com.clinicmanagement.clinic.repository;
import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Patient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;


@Repository
public interface PatientRepository extends JpaRepository<Patient, Integer> {
    List<Patient> findAllByStatus(Boolean status);
    boolean existsByEmail(String email);
    Optional<Patient> findById(Integer id);

    @Query("SELECT p FROM Patient p WHERE p.email = :email AND p.id <> :id")
    Optional<Patient> findByEmailAndNotId(@Param("email") String email, @Param("id") Integer id);
    Patient findByEmail(String email);
}