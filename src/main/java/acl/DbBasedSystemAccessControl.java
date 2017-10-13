package acl;

import com.facebook.presto.spi.CatalogSchemaName;
import com.facebook.presto.spi.CatalogSchemaTableName;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.security.Identity;
import com.facebook.presto.spi.security.Privilege;
import com.facebook.presto.spi.security.SystemAccessControl;
import com.facebook.presto.spi.security.SystemAccessControlFactory;
import com.google.common.collect.ImmutableSet;

import java.security.Principal;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.facebook.presto.spi.security.AccessDeniedException.denyCatalogAccess;
import static com.google.common.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;

public class DbBasedSystemAccessControl
        implements SystemAccessControl {

    public static final String NAME = "db";

    private final List<UserCatalog> userCatalogArrayList;

    private DbBasedSystemAccessControl(List<UserCatalog> userCatalogArrayList) {
        this.userCatalogArrayList = userCatalogArrayList;
    }

    public static class Factory
            implements SystemAccessControlFactory {

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public SystemAccessControl create(Map<String, String> config) {
            requireNonNull(config, "config is null");

            String url = config.get("mysql-url");
            String table = config.get("mysql-table");
            String user = config.get("mysql-user");
            String password = config.get("mysql-password");

            checkState(url != null, "mysql-url must not be null");
            checkState(table != null, "mysql-table must not be null");
            checkState(user != null, "mysql-user must not be null");
            checkState(password != null, "mysql-password must not be null");

            List<UserCatalog> userCatalogArrayList = new ArrayList<>();
            try (Connection c = DriverManager.getConnection(url, user, password)) {
                String sql = "select user, catalog from " + table;
                try (PreparedStatement stmt = c.prepareStatement(sql);
                     ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        userCatalogArrayList.add(new UserCatalog(rs.getString("user"), rs.getString("catalog")));
                    }
                    return new DbBasedSystemAccessControl(userCatalogArrayList);
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void checkCanSetUser(Principal principal, String userName) {
    }

    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, String propertyName) {
    }

    @Override
    public void checkCanAccessCatalog(Identity identity, String catalogName) {
        if (!canAccessCatalog(identity, catalogName)) {
            denyCatalogAccess(catalogName);
        }
    }

    @Override
    public Set<String> filterCatalogs(Identity identity, Set<String> catalogs) {
        ImmutableSet.Builder<String> filteredCatalogs = ImmutableSet.builder();
        for (String catalog : catalogs) {
            if (canAccessCatalog(identity, catalog)) {
                filteredCatalogs.add(catalog);
            }
        }
        return filteredCatalogs.build();
    }

    private boolean canAccessCatalog(Identity identity, String catalogName) {
        for (UserCatalog userCatalog : userCatalogArrayList) {
            if (userCatalog.getUser().equals(identity.getUser()) && userCatalog.getCatalog().equals(catalogName)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema) {
    }

    @Override
    public void checkCanDropSchema(Identity identity, CatalogSchemaName schema) {
    }

    @Override
    public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName) {
    }

    @Override
    public void checkCanShowSchemas(Identity identity, String catalogName) {
    }

    @Override
    public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames) {
        if (!canAccessCatalog(identity, catalogName)) {
            return ImmutableSet.of();
        }

        return schemaNames;
    }

    @Override
    public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanDropTable(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    }

    @Override
    public void checkCanShowTablesMetadata(Identity identity, CatalogSchemaName schema) {
    }

    @Override
    public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames) {
        if (!canAccessCatalog(identity, catalogName)) {
            return ImmutableSet.of();
        }

        return tableNames;
    }

    @Override
    public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanSelectFromTable(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanCreateView(Identity identity, CatalogSchemaTableName view) {
    }

    @Override
    public void checkCanDropView(Identity identity, CatalogSchemaTableName view) {
    }

    @Override
    public void checkCanSelectFromView(Identity identity, CatalogSchemaTableName view) {
    }

    @Override
    public void checkCanCreateViewWithSelectFromTable(Identity identity, CatalogSchemaTableName table) {
    }

    @Override
    public void checkCanCreateViewWithSelectFromView(Identity identity, CatalogSchemaTableName view) {
    }

    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName) {
    }

    @Override
    public void checkCanGrantTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, String grantee, boolean withGrantOption) {
    }

    @Override
    public void checkCanRevokeTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, String revokee, boolean grantOptionFor) {
    }


}
