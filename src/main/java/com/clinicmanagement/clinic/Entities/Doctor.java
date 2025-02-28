package com.clinicmanagement.clinic.Entities;

import jakarta.persistence.*;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "doctor")
public class Doctor {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String fullName;

    private Boolean gender;

    private String phone;

    @Column(name = "email", length = 50, unique = true)
    private String email;

    @ManyToOne
    @JoinColumn(name = "specialization_id")
    private Specialization specialization;

    private Boolean status;
}

