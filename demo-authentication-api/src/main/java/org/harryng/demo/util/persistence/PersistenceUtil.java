package org.harryng.demo.util.persistence;

import org.harryng.demo.util.PageInfo;
import org.harryng.demo.util.PageResult;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaQuery;

public class PersistenceUtil {

    public static <T extends Object> PageResult<T> selectObjectByCriteria(EntityManager entityManager, PageInfo pageInfo, CriteriaQuery<T> criteriaQuery) throws RuntimeException, Exception {
        TypedQuery<T> typedQuery = entityManager.createQuery(criteriaQuery);
        typedQuery.setFirstResult((int) pageInfo.getStartRowIndex());
        typedQuery.setMaxResults(pageInfo.getPageSize());
        PageResult<T> pageResult = new PageResult<>(pageInfo);
        pageResult.getResults().addAll(typedQuery.getResultList());
        return pageResult;
    }

    public static <T extends Object> PageResult<T> selectObjectByQuery(EntityManager entityManager, PageInfo pageInfo, Class<T> typeClass, String queryStr) throws RuntimeException, Exception {
        PageResult<T> pageResult = new PageResult<>(pageInfo);
        TypedQuery<T> typedQuery = entityManager.createQuery(queryStr, typeClass);
        typedQuery.setFirstResult((int) pageInfo.getStartRowIndex());
        typedQuery.setMaxResults(pageInfo.getPageSize());
        pageResult.getResults().addAll(typedQuery.getResultList());
        return pageResult;
    }
}
