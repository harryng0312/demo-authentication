package org.harryng.demo.util;

import java.util.ArrayList;
import java.util.List;

public class PageResult<T extends Object> extends PageInfo {
    private List<T> results = null;

    public PageResult(PageInfo pageInfo) {
        super(pageInfo.getStartPageIndex(), pageInfo.getPageSize());
    }

    public PageResult(long startPageIndex, int pageSize) {
        super(startPageIndex, pageSize);
    }

    public List<T> getResults() {
        if (results == null) {
            results = new ArrayList<>();
        }
        return results;
    }
}
