package id.codecorn.autorizationserver.service;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService implements AuthenticationProvider {
	private final UsersServiceImpl usersServiceImpl;
	private final PasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();
		UserDetails user = usersServiceImpl.loadUserByUsername(username);
		return checkPassword(user, password);
	}

	private Authentication checkPassword(UserDetails user, String rawPassword) {
		if (passwordEncoder.matches(rawPassword, user.getPassword())) {
			return new UsernamePasswordAuthenticationToken(
					user.getUsername(),
					user.getPassword(),
					user.getAuthorities());
		} else {
			throw new BadCredentialsException("Username atau Password anda salah");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
