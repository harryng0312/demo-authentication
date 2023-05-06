package org.harryng.demo.auth.service;

import org.harryng.demo.user.pojo.entity.UserImpl;

public interface AuthService {
    UserImpl loginByUsernamePassword(String username, String password) throws RuntimeException, Exception;
}
