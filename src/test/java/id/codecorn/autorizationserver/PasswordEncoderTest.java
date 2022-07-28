package id.codecorn.autorizationserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
public class PasswordEncoderTest {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Test
	public void generatePassword() {
		String password = passwordEncoder.encode("testPassword");
		System.out.println(password);
	}
}
