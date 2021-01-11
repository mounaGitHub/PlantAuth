package com.projet.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.projet.entities.AppUser;
import com.projet.service.AccountService;

import lombok.Data;

@RestController
public class UserController {

	@Autowired
	AccountService accountService;
	
	@PostMapping("/register")
	public AppUser register(@RequestBody UserForm userForm)
	{
		return accountService.saveUser(userForm.getUserName(),userForm.getEmail(), userForm.getPassword(), userForm.getConfirmedPassword());
	}
}
@Data
class UserForm{
	private String userName;
	private String password;
	private String confirmedPassword;
	private String email;

}