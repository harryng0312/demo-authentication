package org.harryng.demo.base.service;

import org.harryng.demo.base.persistence.BaseSearchablePersistence;
import org.harryng.demo.base.pojo.entity.BaseEntity;
import org.harryng.demo.util.PageInfo;
import org.harryng.demo.util.PageResult;

import javax.persistence.criteria.CriteriaQuery;

public abstract class AbstractSearchableService<Id extends Object, T extends BaseEntity<Id>> extends AbstractService<Id, T> implements BaseSearchableService<Id, T> {

    @Override
    public abstract BaseSearchablePersistence<Id, T> getPersistence();

    @Override
    public PageResult<T> findByConditions(PageInfo pageInfo, CriteriaQuery<T> criteriaQuery) throws RuntimeException, Exception {
        return getPersistence().selectByConditions(pageInfo, criteriaQuery);
    }

    @Override
    public PageResult<T> findByConditions(PageInfo pageInfo, Class<T> entityClass, String queryStr) throws RuntimeException, Exception {
        return getPersistence().selectByConditions(pageInfo, getPersistence().getEntityClass(), queryStr);
    }
}
