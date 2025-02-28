package com.clinicmanagement.clinic.Entities;

import jakarta.persistence.*;

import lombok.*;

import java.time.LocalDate;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name="patient")
public class Patient {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String fullName;
    private LocalDate dob;
    private String address;
    private boolean gender;

    @Column(name = "email", length = 50, unique = true)
    private String email;
    private String phone;

    private  Boolean status;
}
