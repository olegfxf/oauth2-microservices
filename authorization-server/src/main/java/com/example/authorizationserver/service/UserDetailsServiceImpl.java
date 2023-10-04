package com.example.authorizationserver.service;

import com.example.authorizationserver.model.User;
import com.example.authorizationserver.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("qaz1");
        User user = userRepository.findByUsername(username);
        System.out.println(user);

        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        } else {
            System.out.println("qaz2");
            System.out.println(user.getPassword());
            org.springframework.security.core.userdetails.User qaz =  new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    user.getRoles()
                            .stream()
                            .map(role -> new SimpleGrantedAuthority(role))
                            .collect(Collectors.toSet())
            );
            System.out.println(qaz);
            return qaz;
        }
    }
}
