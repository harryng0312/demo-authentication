package org.harryng.demo.base.service;

import org.harryng.demo.base.pojo.entity.BaseEntity;
import org.harryng.demo.util.PageInfo;
import org.harryng.demo.util.PageResult;

import javax.persistence.criteria.CriteriaQuery;

public interface BaseSearchableService<Id extends Object, T extends BaseEntity<Id>> extends BaseService<Id, T> {
    PageResult<T> findByConditions(PageInfo pageInfo, CriteriaQuery<T> criteriaQuery) throws RuntimeException, Exception;
    PageResult<T> findByConditions(PageInfo pageInfo, Class<T> entityClass, String queryStr) throws RuntimeException, Exception;
}
