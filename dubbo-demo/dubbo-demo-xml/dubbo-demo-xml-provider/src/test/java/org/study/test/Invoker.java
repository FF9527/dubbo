package org.study.test;

/**
 * @author:wuqi
 * @date:2020/3/16
 * @description:org.study.test
 * @version:1.0
 */
public class Invoker {
    /*public Object invokeMethod(Object o, String n, Class[] p, Object[] v) throws java.lang.reflect.InvocationTargetException {
        org.study.service.UserService w;
        try {
            w = ((org.study.service.UserService) $1);
        } catch (Throwable e) {
            throw new IllegalArgumentException(e);
        }
        try {
            if ("update".equals($2) && $3.length == 1) {
                w.update((org.study.model.User) $4[0]);
                return null;
            }
            if ("delete".equals($2) && $3.length == 1) {
                w.delete((org.study.model.User) $4[0]);
                return null;
            }
            if ("insert".equals($2) && $3.length == 1) {
                w.insert((org.study.model.User) $4[0]);
                return null;
            }
            if ("getUserById".equals($2) && $3.length == 1) {
                return ($w) w.getUserById((java.lang.Long) $4[0]);
            }
            if ("getUserByUserId".equals($2) && $3.length == 1) {
                return ($w) w.getUserByUserId((java.lang.Long) $4[0]);
            }
            if ("transactionalTest".equals($2) && $3.length == 2) {
                w.transactionalTest((org.study.model.User) $4[0], ((Boolean) $4[1]).booleanValue());
                return null;
            }
        } catch (Throwable e) {
            throw new java.lang.reflect.InvocationTargetException(e);
        }
        throw new org.apache.dubbo.common.bytecode.NoSuchMethodException("Not found method \"" + $2 + "\" in class org.study.service.UserService.");
    }*/
}
