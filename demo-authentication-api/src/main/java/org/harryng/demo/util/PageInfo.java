package org.harryng.demo.util;

import java.io.Serializable;

public class PageInfo implements Serializable {
    private long startPageIndex = 0;
    private int pageSize = 1;

    public PageInfo() {
    }

    public PageInfo(long startPageIndex, int pageSize) {
        this.startPageIndex = startPageIndex;
        this.pageSize = pageSize;
    }

    public long getStartPageIndex() {
        return startPageIndex;
    }

    public void setStartPageIndex(long startPageIndex) {
        startPageIndex = Math.max(0, startPageIndex);
        this.startPageIndex = startPageIndex;
    }

    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(int pageSize) {
        pageSize = Math.max(1, pageSize);
        this.pageSize = pageSize;
    }

    public long getStartRowIndex() {
        long pageIndex = getStartPageIndex() * getPageSize();
        return pageIndex;
    }
}
