package io.robbtsang.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Autowired
	VerificationHelper<String> helper;

    @Override
    public void run(String... args) throws Exception {
        if(helper.verify("consumer.crt", "consumer_expired.crt")) {
            System.out.println("Run real code");
        } else {
            System.out.println("Run dummy code");
        }
    }
}
