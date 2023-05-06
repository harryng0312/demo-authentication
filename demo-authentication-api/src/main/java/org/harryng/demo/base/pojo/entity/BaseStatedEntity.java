package org.harryng.demo.base.pojo.entity;

import java.util.Date;

public interface BaseStatedEntity{
    Date getCreatedDate();
    void setCreatedDate(Date createdDate);
    Date getModifiedDate();
    void setModifiedDate(Date modifiedDate);
    String getStatus();
    void setStatus(String status);
}
