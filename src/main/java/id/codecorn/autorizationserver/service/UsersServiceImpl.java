package id.codecorn.autorizationserver.service;

import java.util.ArrayList;
import java.util.Collection;

import javax.transaction.Transactional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import id.codecorn.autorizationserver.dao.RolesDao;
import id.codecorn.autorizationserver.dao.UsersDao;
import id.codecorn.autorizationserver.entity.Roles;
import id.codecorn.autorizationserver.entity.Users;
import id.codecorn.autorizationserver.exception.UserIsRegisteredException;
import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class UsersServiceImpl implements UsersService, UserDetailsService {
	private final PasswordEncoder passwordEncoder;
	private final UsersDao usersDao;
	private final RolesDao rolesDao;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Users user = usersDao.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("Username atau Passwiod anda salah");
		}

		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(roles -> {
			authorities.add(new SimpleGrantedAuthority(roles.getName()));
		});

		return new User(user.getUsername(), user.getPassword(), authorities);
	}

	@Override
	public Users saveUser(Users user) throws UserIsRegisteredException {
		Users users = usersDao.findByUsername(user.getUsername());
		if (users != null) {
			throw new UserIsRegisteredException("Username sudah digunakan");
		} else {
			user.setPassword(passwordEncoder.encode(user.getPassword()));
			return usersDao.save(user);
		}
	}

	@Override
	public Roles saveRole(Roles roles) {
		return rolesDao.save(roles);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		Users user = usersDao.findByUsername(username);
		Roles role = rolesDao.findByName(roleName);
		user.getRoles().add(role);
	}

}
