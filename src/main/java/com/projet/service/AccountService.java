package com.projet.service;

import com.projet.entities.AppRole;
import com.projet.entities.AppUser;

public interface AccountService {
	
	public AppUser saveUser(String userName, String email, String password, String confirmedPassword);
	public AppRole saveRole(AppRole role);
	public AppUser loadUserByUserName(String userName);
	public void addRoleToUser(String userName, String roleName);

}
