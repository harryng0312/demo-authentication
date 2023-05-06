package org.harryng.demo.base.persistence;

import org.harryng.demo.base.pojo.entity.BaseEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaDelete;
import javax.persistence.criteria.Root;

public abstract class AbstractPersistence<Id extends Object, T extends BaseEntity<Id>> implements BasePersistence<Id, T> {

    @Autowired
    @Qualifier("entityManagerFactory")
    private EntityManager defaultEntityManager;
    private Class<T> entityClass = null;

    public AbstractPersistence(Class<T> entityClass) {
        this.entityClass = entityClass;
    }

    @Override
    public Class<T> getEntityClass() {
        return entityClass;
    }

    @Override
    public EntityManager getEntityManager() {
        return defaultEntityManager;
    }

    @Override
    public EntityManager getEntityManager(String entityManagerName) {
        return null;
    }

    @Override
    public T selectById(Id id) throws RuntimeException, Exception {
        return getEntityManager().find(getEntityClass(), id);
    }

    @Override
    public int insert(T obj) throws RuntimeException, Exception {
        getEntityManager().persist(obj);
        return 1;
    }

    @Override
    public int update(T obj) throws RuntimeException, Exception {
        getEntityManager().merge(obj);
        return 1;
    }

    @Override
    public int delete(Id id) throws RuntimeException, Exception {
        CriteriaBuilder cb = getEntityManager().getCriteriaBuilder();
        CriteriaDelete<T> criteriaDelete = cb.createCriteriaDelete(getEntityClass());
        Root<T> root = criteriaDelete.from(getEntityClass());
        criteriaDelete.where(cb.equal(root.get("id"), id));
        Query query = getEntityManager().createQuery(criteriaDelete);
        int rs = query.executeUpdate();
        return rs;
    }
}
