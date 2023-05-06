package org.harryng.demo.user.service;

import org.harryng.demo.base.persistence.BaseSearchablePersistence;
import org.harryng.demo.base.service.AbstractSearchableService;
import org.harryng.demo.user.persistence.UserPersistence;
import org.harryng.demo.user.pojo.entity.UserImpl;
import org.harryng.demo.util.PageInfo;
import org.harryng.demo.util.PageResult;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;

public class UserServiceImpl extends AbstractSearchableService<Long, UserImpl> implements UserService {

    @Autowired
    private UserPersistence userPersistence;

    @Override
    public BaseSearchablePersistence<Long, UserImpl> getPersistence() {
        return userPersistence;
    }

    @Override
    public UserImpl getByUsername(String username) throws RuntimeException, Exception {
        UserImpl result = null;
        PageInfo pageInfo = new PageInfo();
        CriteriaBuilder criteriaBuilder = getPersistence().getEntityManager().getCriteriaBuilder();
        CriteriaQuery<UserImpl> criteriaQuery = criteriaBuilder.createQuery(UserImpl.class);
        Root<UserImpl> root = criteriaQuery.from(UserImpl.class);
        criteriaQuery.where(criteriaBuilder.equal(root.get("username"), username));
        PageResult<UserImpl> pageResult = findByConditions(pageInfo, criteriaQuery);
        if (pageResult.getResults().size() > 0) {
            result = pageResult.getResults().get(0);
        }
        return result;
    }
}
