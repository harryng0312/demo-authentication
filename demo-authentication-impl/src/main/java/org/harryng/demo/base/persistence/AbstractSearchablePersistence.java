package org.harryng.demo.base.persistence;

import org.harryng.demo.base.pojo.entity.BaseEntity;
import org.harryng.demo.util.PageInfo;
import org.harryng.demo.util.PageResult;
import org.harryng.demo.util.persistence.PersistenceUtil;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaQuery;

public abstract class AbstractSearchablePersistence<Id extends Object, T extends BaseEntity<Id>> extends AbstractPersistence<Id, T> implements BaseSearchablePersistence<Id, T> {

    public AbstractSearchablePersistence(Class<T> entityClass) {
        super(entityClass);
    }

    @Override
    public PageResult<T> selectByConditions(PageInfo pageInfo, CriteriaQuery<T> criteriaQuery) throws RuntimeException, Exception {
        PageResult<T> pageResult = PersistenceUtil.selectObjectByCriteria(getEntityManager(), pageInfo, criteriaQuery);
        return pageResult;
    }

    @Override
    public PageResult<T> selectByConditions(PageInfo pageInfo, Class<T> entityClass, String queryStr) throws RuntimeException, Exception {
        PageResult<T> pageResult = PersistenceUtil.selectObjectByQuery(getEntityManager(), pageInfo, getEntityClass(), queryStr);
        return pageResult;
    }
}
