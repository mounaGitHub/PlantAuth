package com.projet.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.projet.dao.AppRoleRepository;
import com.projet.dao.AppUserRepository;
import com.projet.entities.AppRole;
import com.projet.entities.AppUser;

@Service
@Transactional
public class AccountServiceImpl implements AccountService{

	@Autowired
	private AppUserRepository appUserRepository;
	@Autowired
	private AppRoleRepository appRoleRepository;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Override
	public AppUser saveUser(String userName, String email,String password, String confirmedPassword) {
	    System.out.println("userName"+userName);
		AppUser user = appUserRepository.findByUserName(userName);
		if(user != null ) throw new RuntimeException(userName+"User already exists");
		if(!password.equals(confirmedPassword)) throw new RuntimeException("Please confirm your password");
		AppUser appUser = new AppUser();
		appUser.setUserName(userName);
		appUser.setEmail(email);
		appUser.setActivated(true);
		appUser.setPassword(bCryptPasswordEncoder.encode(password));
		appUserRepository.save(appUser);
		addRoleToUser(userName, "USER");
		return appUser;
	}

	@Override
	public AppRole saveRole(AppRole role) {
		return appRoleRepository.save(role);
	}

	@Override
	public AppUser loadUserByUserName(String userName) {
		AppUser appUser = appUserRepository.findByUserName(userName);
		System.out.println("loadUserByUserName"+appUser.getRoles().size()+appUser.getUserName()+appUser.getPassword());
		return appUser;
	}

	@Override
	public void addRoleToUser(String userName, String roleName) {
		
		AppUser user = appUserRepository.findByUserName(userName);
		System.out.println("*****role="+roleName);
		AppRole role = appRoleRepository.findByRoleName(roleName);
		user.getRoles().add(role);
	}

}
