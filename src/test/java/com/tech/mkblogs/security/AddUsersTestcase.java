package com.tech.mkblogs.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.tech.mkblogs.security.db.AccountUserRepository;
import com.tech.mkblogs.security.db.model.Authorities;
import com.tech.mkblogs.security.db.model.User;

import lombok.extern.log4j.Log4j2;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Log4j2
public class AddUsersTestcase {

	@BeforeAll
	public static void beforeEachTest() throws Exception {
		log.info("==================================================================================");
		log.info("This is executed before each Test");
	}

	@AfterAll
	public static void afterEachTest() {		
		log.info("This is exceuted after each Test");
		log.info("==================================================================================");
	}
	
	@Test
	public void saveUserWithAuthorities(@Autowired AccountUserRepository repository) {
		log.info(repository);
		User user = new User();
		user.setLoginName("Test");
		user.setPassword("Test");
		user.setAccountExpired(false);
		user.setAccountLocked(false);
		user.setEnabled(false);
		user.setCredentialsExpired(false);
		Authorities auth = new Authorities();
		auth.setAuthority("ROLE_USER");
		user.addAuthorities(auth);
		System.out.println(user);
		repository.save(user);
	}
	
	@Test
	@Transactional
	public void getUserWithAuthorities(@Autowired AccountUserRepository repository) {
		User user = repository.findByLoginName("first");
		System.out.println(user);
		System.out.println(user.getAuthorities());
		
	}
	
	@Test
	public void testBCrypt() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("second");
		System.out.println(result);
		System.out.println(encoder.matches("second", result)); 
	}
}
