package com.rashad.springJwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {
    @Autowired
	private JavaMailSender mailSender;

	public void sendEmail(String to, String subject, String content) {
        MimeMessage message = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
			helper.setFrom("rashadchowki42@gmail.com");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, true); 
            mailSender.send(message);
        } catch (MessagingException e) {
			System.out.println("mail can't be sent..");
		}
	}
}
