package org.harryng.demo.user.service;

import org.harryng.demo.base.service.BaseSearchableService;
import org.harryng.demo.user.pojo.entity.UserImpl;

public interface UserService extends BaseSearchableService<Long, UserImpl> {
    UserImpl getByUsername(String username) throws RuntimeException, Exception;
}
