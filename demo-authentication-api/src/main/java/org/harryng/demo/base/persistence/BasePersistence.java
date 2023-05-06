package org.harryng.demo.base.persistence;

import org.harryng.demo.base.pojo.entity.BaseEntity;

import javax.persistence.EntityManager;

public interface BasePersistence<Id extends Object, T extends BaseEntity<Id>> {
    EntityManager getEntityManager();
    EntityManager getEntityManager(String entityManagerName);
    Class<T> getEntityClass();

    T selectById(Id id) throws RuntimeException, Exception;
    int insert(T obj) throws RuntimeException, Exception;
    int update(T obj) throws RuntimeException, Exception;
    int delete(Id id) throws RuntimeException, Exception;
}
