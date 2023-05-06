package org.harryng.demo.auth.service;

import org.harryng.demo.user.pojo.entity.UserImpl;
import org.harryng.demo.user.service.UserService;
import org.harryng.demo.util.SecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;

public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserService userService;

    @Override
    public UserImpl loginByUsernamePassword(String username, String password) throws RuntimeException, Exception {
        UserImpl user = userService.getByUsername(username);
        if (password == null) {
            throw new Exception("Password is not valid");
        }
        if (user != null) {
            if ("plain".equalsIgnoreCase(user.getPasswdEncryptedMethod())) {
                if (!password.equals(user.getPasswd())) {
                    throw new Exception("Username or Password is not matched");
                }
            } else {
                byte[] inputPasswdBin = password.getBytes("UTF-8");
                byte[] inputHashedPasswdBin = SecurityUtil.hashMessage(user.getPasswdEncryptedMethod(), inputPasswdBin);
                String inputHashedPasswd = new String(inputHashedPasswdBin);
                if (!inputHashedPasswd.equals(user.getPasswd())) {
                    throw new Exception("Password is not matched");
                }
            }
        } else {
            throw new Exception("User is not found");
        }
        return user;
    }
}
