package com.example.demo.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

public class ApplicationUser implements UserDetails {

    private final String password;
    private final String username;
    private final Set<? extends GrantedAuthority> grantedAuthorities;
    private final boolean isAccaoutNonExpired;
    private final boolean isAccaoutNonLocked;
    private final boolean isCredentialsNonExpired;
    private final boolean isEnabled;

    public ApplicationUser(String password, String username, Set<? extends GrantedAuthority> grantedAuthorities, boolean isAccaoutNonExpired, boolean isAccaoutNonLocked, boolean isCredentialsNonExpired, boolean isEnabled) {
        this.password = password;
        this.username = username;
        this.grantedAuthorities = grantedAuthorities;
        this.isAccaoutNonExpired = isAccaoutNonExpired;
        this.isAccaoutNonLocked = isAccaoutNonLocked;
        this.isCredentialsNonExpired = isCredentialsNonExpired;
        this.isEnabled = isEnabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccaoutNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccaoutNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }
}
