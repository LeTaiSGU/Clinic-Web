package com.clinicmanagement.clinic.service;


import com.clinicmanagement.clinic.Entities.appointment_service;
import com.clinicmanagement.clinic.repository.appointment_serviceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class appointment_serviceService {
    @Autowired
    private appointment_serviceRepository _appointment_serviceRepository;

    public boolean add(appointment_service appointment_service) {
        try {
           var result = _appointment_serviceRepository.save(appointment_service);
           if(result==null)
               return false;

           return true;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public void saveAll(List<appointment_service> appointment_services) {
        _appointment_serviceRepository.saveAll(appointment_services);
    }
}
