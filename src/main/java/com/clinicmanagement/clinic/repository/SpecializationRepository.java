package com.clinicmanagement.clinic.repository;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Specialization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SpecializationRepository extends JpaRepository<Specialization, Integer> {
    List<Specialization> findAllByStatus(Boolean status);
    Optional<Specialization> findById(Integer id);

    Specialization findByName(String name);

    @Query("SELECT s FROM Specialization s WHERE s.name = :name AND s.id <> :id")
    Specialization findByNameAndNotId(@Param("name") String name, @Param("id") Integer id);
}
