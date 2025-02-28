package com.clinicmanagement.clinic.repository;

import com.clinicmanagement.clinic.Entities.Appointment;
import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Patient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface AppointmentRepository extends JpaRepository<Appointment, Integer> {
/*    @Query("SELECT a FROM Appointment a " +
            "JOIN a.appointmentServices asv " +
            "JOIN asv.services s " +
            "WHERE (LOWER(a.status) LIKE LOWER(CONCAT('%', :keyword, '%'))) " +
            "OR (LOWER(s.serviceName) LIKE LOWER(CONCAT('%', :keyword, '%'))) " +
            "OR (CAST(a.appointmentDate AS string) LIKE LOWER(CONCAT('%', :keyword, '%'))) " +
            "OR (CAST(a.appointmentTime AS string) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    List<Appointment> searchAppointments(@Param("keyword") String keyword);*/

    @Query("SELECT DISTINCT a FROM Appointment a " +
            "LEFT JOIN a.appointmentServices asv " +
            "LEFT JOIN asv.services s " +
            "WHERE (:keyword IS NULL OR " +
            "LOWER(a.status) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(s.serviceName) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR CAST(a.appointmentDate AS string) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR CAST(a.appointmentTime AS string) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    List<Appointment> searchAppointments(@Param("keyword") String keyword);

    List<Appointment> findByPatient(Patient patient);

    List<Appointment> findByDoctorAndAppointmentDate(Doctor doctor, LocalDate appointmentDate);


}
