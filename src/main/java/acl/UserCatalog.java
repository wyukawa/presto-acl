package acl;

public class UserCatalog {

    private final String user;

    private final String catalog;

    public UserCatalog(String user, String catalog) {
        this.user = user;
        this.catalog = catalog;
    }

    public String getUser() {
        return user;
    }

    public String getCatalog() {
        return catalog;
    }


}
