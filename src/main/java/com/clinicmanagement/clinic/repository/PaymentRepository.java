package com.clinicmanagement.clinic.repository;

import com.clinicmanagement.clinic.Entities.payment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PaymentRepository extends JpaRepository<payment, Integer> {

    @Query("SELECT p FROM payment p JOIN p.appointment a WHERE a.patient.id = :patientId ORDER BY p.paymentDate DESC")
    List<payment> findByPatientId(Integer patientId);

    @Query("SELECT p FROM payment p " +
            "WHERE p.appointment.patient.id = :patientId AND " +
            "(LOWER(CAST(p.id AS string)) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(CAST(p.appointment.id AS string)) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(p.paymentMethod) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(p.status) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    List<payment> findByKeywordAndPatient(
            @Param("keyword") String keyword,
            @Param("patientId") int patientId
    );
}
