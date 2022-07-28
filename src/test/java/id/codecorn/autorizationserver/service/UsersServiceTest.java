package id.codecorn.autorizationserver.service;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import id.codecorn.autorizationserver.entity.Roles;
import id.codecorn.autorizationserver.entity.Users;
import id.codecorn.autorizationserver.exception.UserIsRegisteredException;

@SpringBootTest
public class UsersServiceTest {

	@Autowired
	private UsersService usersService;

	@Test
	public void registerUserTest() throws UserIsRegisteredException {
		usersService.saveRole(new Roles(null, "ROLE_ADMIN"));

		Users data = new Users();
		data.setUsername("admin");
		data.setPassword("admin123");
		data.setEmail("hermantolakoro@gmail.com");
		data.setNoHp("0000");

		usersService.saveUser(data);
		usersService.addRoleToUser("admin", "ROLE_ADMIN");
	}

}
