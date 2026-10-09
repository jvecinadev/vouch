// expect: CWE-89
package benchmark.cases;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class sqli_java_01 {
    public ResultSet login(Connection conn, String email) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE email = '" + email + "'";
        return stmt.executeQuery(query);
    }
}
