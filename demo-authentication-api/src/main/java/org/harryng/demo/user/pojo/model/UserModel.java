package org.harryng.demo.user.pojo.model;

import org.harryng.demo.base.pojo.entity.AbstractStatedEntity;

import java.util.Date;

public class UserModel extends AbstractStatedEntity<Long> {
    private String username;
    private String passwd;
    private String screenName;
    private Date dob;
    private String passwdEncryptedMethod;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswd() {
        return passwd;
    }

    public void setPasswd(String passwd) {
        this.passwd = passwd;
    }

    public String getScreenName() {
        return screenName;
    }

    public void setScreenName(String screenName) {
        this.screenName = screenName;
    }

    public Date getDob() {
        return dob;
    }

    public void setDob(Date dob) {
        this.dob = dob;
    }

    public String getPasswdEncryptedMethod() {
        return passwdEncryptedMethod;
    }

    public void setPasswdEncryptedMethod(String passwdEncryptedMethod) {
        this.passwdEncryptedMethod = passwdEncryptedMethod;
    }
}
