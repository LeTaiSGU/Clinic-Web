package com.clinicmanagement.clinic.service;

import org.eclipse.angus.mail.imap.protocol.MailboxInfo;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender javaMailSender;

    public EmailService(JavaMailSender javaMailSender){
        this.javaMailSender = javaMailSender;
    }

    @Async
    public void sendSimpleEmail(String to, String subject, String text){
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("letaikun11112@gmail.com");
        message.setTo(to.trim());
        message.setSubject(subject);
        message.setText(text);
        javaMailSender.send(message);
    }

}
