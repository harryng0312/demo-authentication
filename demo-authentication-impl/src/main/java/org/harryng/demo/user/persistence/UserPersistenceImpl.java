package org.harryng.demo.user.persistence;

import org.harryng.demo.base.persistence.AbstractSearchablePersistence;
import org.harryng.demo.user.pojo.entity.UserImpl;

public class UserPersistenceImpl extends AbstractSearchablePersistence<Long, UserImpl> implements UserPersistence {
    public UserPersistenceImpl() {
        super(UserImpl.class);
    }
}
