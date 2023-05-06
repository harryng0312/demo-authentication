package org.harryng.demo.base.pojo.entity;

public abstract class AbstractEntity<Id extends Object> implements BaseEntity<Id> {
    private Id id;

    @Override
    public Id getId() {
        return id;
    }

    @Override
    public void setId(Id id) {
        this.id = id;
    }
}
