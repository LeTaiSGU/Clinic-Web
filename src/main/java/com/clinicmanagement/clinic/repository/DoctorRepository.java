package com.clinicmanagement.clinic.repository;

import com.clinicmanagement.clinic.Entities.Doctor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DoctorRepository extends JpaRepository<Doctor, Integer> {

    List<Doctor> findAllByStatus(Boolean status);


    Optional<Doctor> findById(Integer id);
    Doctor findByEmail(String email);

    @Query("SELECT d FROM Doctor d WHERE d.email = :email AND d.id <> :id")
    Optional<Doctor> findByEmailAndNotId(@Param("email") String email, @Param("id") Integer id);
}

