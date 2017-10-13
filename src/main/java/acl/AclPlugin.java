package acl;

import com.facebook.presto.spi.Plugin;
import com.facebook.presto.spi.security.SystemAccessControlFactory;
import com.google.common.collect.ImmutableList;

public class AclPlugin implements Plugin {

    @Override
    public Iterable<SystemAccessControlFactory> getSystemAccessControlFactories() {
        return ImmutableList.of(new DbBasedSystemAccessControl.Factory());
    }

}