package org.harryng.demo.base.service;

import org.harryng.demo.base.persistence.BasePersistence;
import org.harryng.demo.base.pojo.entity.BaseEntity;

public abstract class AbstractService<Id extends Object, T extends BaseEntity<Id>> implements BaseService<Id, T> {

    @Override
    public abstract BasePersistence<Id, T> getPersistence();

    @Override
    public T getById(Id id) throws RuntimeException, Exception {
        return getPersistence().selectById(id);
    }

    @Override
    public int add(T obj) throws RuntimeException, Exception {
        return getPersistence().insert(obj);
    }

    @Override
    public int edit(T obj) throws RuntimeException, Exception {
        return getPersistence().update(obj);
    }

    @Override
    public int remove(Id id) throws RuntimeException, Exception {
        return getPersistence().delete(id);
    }
}
