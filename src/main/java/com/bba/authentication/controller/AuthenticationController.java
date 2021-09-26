package com.bba.authentication.controller;

import com.bba.authentication.security.JwtTokenUtil;
import com.bba.authentication.security.JwtUserDetailsService;
import com.bba.authentication.ui.beans.LoginInput;
import com.bba.authentication.ui.beans.LoginOutput;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/authenticate")
public class AuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private JwtUserDetailsService userDetailsService;

	@PostMapping
	public LoginOutput login(@RequestBody LoginInput loginInput, HttpServletRequest request) throws Exception {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginInput.getUserName(),
							loginInput.getPassword()));
		}
		catch (BadCredentialsException e) {
			throw new Exception("Incorrect username or password", e);
		}
		LoginOutput loginOutput = new LoginOutput();
		final UserDetails userDetails = userDetailsService
				.loadUserByUsername(loginInput.getUserName());

		final String jwt = jwtTokenUtil.generateToken(userDetails, request.getRemoteAddr());
		loginOutput.setToken(jwt);
		return loginOutput;
	}
}
