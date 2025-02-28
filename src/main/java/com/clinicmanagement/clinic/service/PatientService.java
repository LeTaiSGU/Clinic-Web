package com.clinicmanagement.clinic.service;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.repository.PatientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public class PatientService {

    @Autowired
    private PatientRepository patientRepository;

    public List<Patient> getAllPatients() {
        List<Patient> patients = patientRepository.findAll();
        return patients;
    }

    public Page<Patient> getAllPatientPage(Pageable pageable) {
        return patientRepository.findAll(pageable);
    }

    public List<Patient> findAllByStatus(Boolean status) {
        return patientRepository.findAllByStatus(status);
    }

    public Patient findById(Integer patientID) {
        return patientRepository.findById(patientID)
                .orElseThrow(() -> new RuntimeException("Patient not found"));
    }

    public Optional<Patient> findByEmailAndNotId(String email, Integer id) {
        return patientRepository.findByEmailAndNotId(email, id);
    }

    public Patient savePatient(Patient patient) {
        return patientRepository.save(patient);
    }

    public Patient findByEmail(String email) {
        return patientRepository.findByEmail(email);
    }

    public boolean checkByEmail(String email){
        return patientRepository.existsByEmail(email);
    }
}
