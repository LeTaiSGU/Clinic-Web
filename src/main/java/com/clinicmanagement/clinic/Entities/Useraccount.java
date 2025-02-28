package com.clinicmanagement.clinic.Entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity
@Table(name="useraccount")
public class Useraccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer id;

    String username;
    String password;

    @ManyToOne
    @JoinColumn(name = "patientId", nullable = true)
    Patient patient;

    @ManyToOne
    @JoinColumn(name = "doctorId", nullable = true)
    Doctor doctor;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER)
    Set<UserRole> userRoles;
    boolean status;

    @Column(name = "reset_password_token")
    private String resetPasswordToken;
}
