package org.harryng.demo.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.harryng.demo.auth.pojo.text.AuthenticationInfo;
import org.harryng.demo.auth.service.AuthService;
import org.harryng.demo.session.SessionHolder;
import org.harryng.demo.user.pojo.entity.UserImpl;
import org.harryng.demo.util.TextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@Controller
public class AuthController {

    static Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    protected HttpServletRequest request;

    @Autowired
    protected AuthService authService;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String initLogin() {
        return "auth/login";
    }

    @RequestMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE, method = RequestMethod.POST)
    @ResponseBody
    public String doLogin(@RequestBody String body) {
        String response = "";
        try {
            AuthenticationInfo authenticationInfo = TextUtil.jsonToObj(AuthenticationInfo.class, body);
            String username = authenticationInfo.getUsername();
            String password = authenticationInfo.getPassword();
            UserImpl user = authService.loginByUsernamePassword(username, password);
            authenticationInfo.setResult("0");
            SessionHolder.getSession(authenticationInfo.getUsername()).put(SessionHolder.K_USER, user);
            SessionHolder.getSession(authenticationInfo.getUsername()).put(SessionHolder.K_AUTH_INFO, authenticationInfo);
            response = TextUtil.objToJson(authenticationInfo);
        } catch (Exception e) {
            AuthenticationInfo authenticationInfoErr = new AuthenticationInfo();
            authenticationInfoErr.setResult("10");
            try {
                response = TextUtil.objToJson(authenticationInfoErr);
            } catch (JsonProcessingException ex) {
                logger.info("", ex);
            }
            logger.error("", e);
        }
        return response;
    }

    @RequestMapping(value = "/afterLogin", method = RequestMethod.GET)
    public String submitLogin(@RequestParam(name = "tokenId", defaultValue = "") String tokenId) {
        String rs = "auth/login";
        boolean result = false;
        result = SessionHolder.getSession(tokenId, false) != null;
        if (result) {
            rs = String.format("redirect:%s", "welcome");
        }
        return rs;
    }

    @RequestMapping(value = "/postUsername", method = RequestMethod.GET)
    public String postUsername(@RequestParam(name="uname", defaultValue = "") String username){
        String rs = "";
        // check username is existed
        // generate salts for username and password
        return rs;
    }

    @RequestMapping(value = "/welcome", method = RequestMethod.GET)
    public String welcome() {
        return "auth/welcome";
    }
}
