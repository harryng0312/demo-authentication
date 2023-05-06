package org.harryng.demo.auth.pojo.text;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.io.Serializable;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "id",
        "username",
        "password",
        "requestTime",
        "result"
})
public class AuthenticationInfo implements Serializable {
    private String id = null;
    private String username = null;
    private String password = null;
    private Date requestTime = null;
    private String result = null;

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("username")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty("password")
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @JsonProperty("requestTime")
    public Date getRequestTime() {
        return requestTime;
    }

    public void setRequestTime(Date requestTime) {
        this.requestTime = requestTime;
    }

    @JsonProperty("result")
    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }
}
