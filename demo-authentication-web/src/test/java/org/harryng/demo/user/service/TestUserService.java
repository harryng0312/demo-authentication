package org.harryng.demo.user.service;

import org.harryng.demo.main.Application;
import org.harryng.demo.user.pojo.entity.UserImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Calendar;
import java.util.Date;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)
@Import(Application.class)
public class TestUserService {

    static Logger logger = LoggerFactory.getLogger(TestUserService.class);

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private UserService userService;

    @Test
    public void testAddUser() throws Exception {
        Date now = Calendar.getInstance().getTime();
        UserImpl user = new UserImpl();
        user.setId(1L);
        user.setUsername("username01");
        user.setPasswd("passwd01");
        user.setScreenName("screen01");
        user.setDob(now);
        user.setPasswdEncryptedMethod("plain");

        user.setCreatedDate(now);
        user.setModifiedDate(now);
        user.setStatus("active");
        int rs = userService.add(user);
        logger.info("Add " + rs + " record(s)");
    }

    @Test
    public void testGetUser() throws Exception {
        UserImpl user = userService.getById(1L);
        logger.info("User:" + user.getUsername());
    }
}
