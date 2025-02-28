package com.clinicmanagement.clinic.repository;

import com.clinicmanagement.clinic.Entities.Services;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ServicesRepository extends JpaRepository<Services,Integer> {

    Optional<Services> findById(Integer integer);

    Services findByServiceName(String serviceName);

    @Query("SELECT s FROM Services s WHERE s.serviceName = :serviceName AND s.id <> :id")
    Optional<Services> findByServiceNameAndNotId(@Param("serviceName") String serviceName, @Param("id") Integer id);
}
