import os
import snowflake.connector
import argparse
import json
import fnmatch

def apply_permissions(snowflake_account, snowflake_user, snowflake_role, snowflake_warehouse, snowflake_region,
                      permissions_file, grant_statements_file, revoke_statements_file, verbose):
    if os.environ["SNOWSQL_PWD"] is None:
        raise ValueError("The SNOWSQL_PWD environment variable has not been defined")
    os.environ["SNOWFLAKE_ACCOUNT"] = snowflake_account
    os.environ["SNOWFLAKE_USER"] = snowflake_user
    os.environ["SNOWFLAKE_ROLE"] = snowflake_role
    os.environ["SNOWFLAKE_WAREHOUSE"] = snowflake_warehouse
    os.environ["SNOWFLAKE_REGION"] = snowflake_region
    os.environ["SNOWFLAKE_AUTHENTICATOR"] = 'snowflake'

    all_databases = fetch_databases(verbose)
    print("databases found: {0}".format(all_databases))
    with open(permissions_file) as f:
        permissions_json = json.load(f)

    all_missing_privileges_string = "BEGIN TRANSACTION;\n"
    all_superfluous_privileges_string = "BEGIN TRANSACTION;\n"

    all_warehouses = fetch_warehouses(verbose)
    existing_warehouse_grants = generate_existing_warehouse_privileges(all_warehouses,verbose)
    existing_database_grants = generate_existing_database_privileges(all_databases,verbose)
    all_defined_warehouse_privileges = []
    all_defined_database_privileges = []

    for account_object_privilege in permissions_json["accountObjectPrivileges"]:
        print("Applying rule {0}".format(account_object_privilege["Purpose"]))
        if account_object_privilege.get("Warehouses") != None and account_object_privilege.get("Databases") != None:
            raise ValueError("Account Object rule has both Warehouses and Databases defined, please choose one of these")

        if account_object_privilege.get("Warehouses") != None:
            for privilege in account_object_privilege["Privileges"]:
                for warehouse in [x for x in all_warehouses if fnmatch.fnmatch(x, account_object_privilege.get("Warehouses"))]:
                    all_defined_warehouse_privileges.append("GRANT {0} ON WAREHOUSE {1} TO ROLE {2}".format(privilege,warehouse,account_object_privilege["Role"]))

        if account_object_privilege.get("Databases") != None:
            for privilege in account_object_privilege["Privileges"]:
                for database in [x for x in all_databases if fnmatch.fnmatch(x, account_object_privilege.get("Databases"))]:
                    all_defined_database_privileges.append(
                        "GRANT {0} ON DATABASE {1} TO ROLE {2}".format(privilege, database, account_object_privilege["Role"]))

    all_missing_warehouse_privileges = (list(set(all_defined_warehouse_privileges) - set(existing_warehouse_grants)))
    all_superfluous_warehouse_privileges = (list(set(existing_warehouse_grants) - set(all_defined_warehouse_privileges)))
    all_missing_database_privileges = (list(set(all_defined_database_privileges) - set(existing_database_grants)))
    all_superfluous_database_privileges = (list(set(existing_database_grants) - set(all_defined_database_privileges)))
    if verbose:
        print("Statements to grant existing warehouse privileges in account: {0}".format(all_missing_warehouse_privileges))
        print("Statements to revoke superfluous warehouse privileges in account: {0}".format(all_superfluous_warehouse_privileges))
        print("Statements to grant existing database privileges in account: {0}".format(all_missing_database_privileges))
        print("Statements to revoke superfluous database privileges in account: {0}".format(all_superfluous_database_privileges))

    all_missing_privileges_string = "{0}\n\n// ========================== Account object privileges".format(all_missing_privileges_string)

    if len(all_missing_warehouse_privileges) > 0:
        all_missing_privileges_string = "{0}\n// ----- Warehouse Privileges\n{1};".format(
            all_missing_privileges_string,
            ";\n".join(all_missing_warehouse_privileges))

    if len(all_missing_database_privileges) > 0:
        all_missing_privileges_string = "{0}\n// ----- Database Privileges\n{1};".format(
            all_missing_privileges_string,
            ";\n".join(all_missing_database_privileges))

    all_superfluous_privileges_string = "{0}\n\n// ========================== Account object privileges".format(all_superfluous_privileges_string)

    if len(all_superfluous_warehouse_privileges) > 0:
        all_superfluous_privileges_string = "{0}\n// ----- Warehouse Privileges\n{1};".format(
            all_superfluous_privileges_string,
            ";\n".join(all_superfluous_warehouse_privileges).replace('GRANT ', 'REVOKE ').replace(' TO ROLE ', ' FROM ROLE '))

    if len(all_superfluous_database_privileges) > 0:
        all_superfluous_privileges_string = "{0}\n// ----- Database Privileges\n{1};".format(
            all_superfluous_privileges_string,
            ";\n".join(all_superfluous_database_privileges).replace('GRANT ', 'REVOKE ').replace(' TO ROLE ', ' FROM ROLE '))


    # for each database, gather all existing grant statements
    all_defined_schema_privileges={}
    all_defined_schema_object_privileges={}
    existing_database_schema_object_grants={}
    existing_database_schema_grants={}
    for database in all_databases:
        existing_database_schema_grants[database] = generate_existing_schema_privileges_sql(database, verbose)
        existing_database_schema_object_grants[database] = generate_existing_table_and_view_privileges_sql(database, verbose)
        all_defined_schema_privileges[database]=set()
        all_defined_schema_object_privileges[database]=set()
        if verbose:
            print("Statements to grant existing schema privileges in database '{0}': {1}".format(database,existing_database_schema_grants[database]))
            print("Statements to grant existing schema object privileges in database '{0}': {1}".format(database,existing_database_schema_object_grants[database]))


    # iterate through the privilege rules defined in the file.
    # for each rule, generate all grant statements required to bring it into effect,
    # storing them grouped by database. Using sets will eliminate any rule overlap and prevent duplicate grant statements
    for schema_privilege in permissions_json["schemaPrivileges"]:
        print("Applying rule {0}".format(schema_privilege["Purpose"]))
        selected_databases = [x for x in all_databases if fnmatch.fnmatch(x,schema_privilege["Databases"])]
        print(selected_databases)
        for database in selected_databases:
            print("Applying rule to database {0}".format(database))
            print("Generating SQL script to determine existing privileges")

            grant_privileges_sql_statements = generate_grant_schema_privileges_sql(database,
                                                                 schema_privilege["Role"],
                                                                 schema_privilege["Schemas"],
                                                                 schema_privilege["Privileges"],
                                                                 verbose)

            all_defined_schema_privileges[database]=all_defined_schema_privileges[database].union(grant_privileges_sql_statements)

    for schema_object_privilege in permissions_json["schemaObjectPrivileges"]:
        print("Applying rule {0}".format(schema_object_privilege["Purpose"]))
        selected_databases = [x for x in all_databases if fnmatch.fnmatch(x,schema_object_privilege["Databases"])]
        print(selected_databases)
        for database in selected_databases:
            print("Applying rule to database {0}".format(database))
            print("Generating SQL script to determine existing privileges")

            grant_privileges_sql_statements = generate_grant_privileges_sql(database,
                                                                 schema_object_privilege["Role"],
                                                                 schema_object_privilege["Schemas"],
                                                                 schema_object_privilege["Tables"],
                                                                 schema_object_privilege["Views"],
                                                                 schema_object_privilege["Privileges"],
                                                                 verbose)

            all_defined_schema_object_privileges[database]=all_defined_schema_object_privileges[database].union(grant_privileges_sql_statements)

    # for each database, produce lists of both missing and superfluous statements (the latter being REVOKEs),
    # such that running them all should bring the database in sync with the rules file
    all_missing_schema_privileges={}
    all_superfluous_schema_privileges={}
    all_missing_schema_object_privileges={}
    all_superfluous_schema_object_privileges={}

    for database in all_databases:
        all_missing_schema_privileges[database] = (list(set(all_defined_schema_privileges[database]) - set(existing_database_schema_grants[database])))
        all_superfluous_schema_privileges[database] = list(set(existing_database_schema_grants[database]) - set(all_defined_schema_privileges[database]))

        all_missing_schema_object_privileges[database] = (list(set(all_defined_schema_object_privileges[database]) - set(existing_database_schema_object_grants[database])))
        all_superfluous_schema_object_privileges[database] = list(set(existing_database_schema_object_grants[database]) - set(all_defined_schema_object_privileges[database]))

        all_missing_privileges_string = "{0}\n\n// ==========================\n// ------ Database {1}\n// ==========================".format(
            all_missing_privileges_string,
            database)

        if len(all_missing_schema_privileges[database]) > 0:
            all_missing_privileges_string = "{0}\n// ----- Schema Privileges\n{1};".format(
                all_missing_privileges_string,
                ";\n".join(all_missing_schema_privileges[database]))

        if len(all_missing_schema_object_privileges[database]) > 0:
            all_missing_privileges_string = "{0}\n// ----- Schema Object Privileges\n{1};".format(
                all_missing_privileges_string,
                ";\n".join(all_missing_schema_object_privileges[database]))

        all_superfluous_privileges_string = "{0}\n\n// ==========================\n// ------ Database {1}\n// ==========================".format(
            all_superfluous_privileges_string,
            database)


        if len(all_superfluous_schema_privileges[database]) > 0:
            all_superfluous_privileges_string = "{0}\n// ----- Schema Privileges\n{1};".format(
                all_superfluous_privileges_string,
                ";\n".join(all_superfluous_schema_privileges[database]).replace('GRANT ','REVOKE ').replace(' TO ROLE ',' FROM ROLE '))

        if len(all_superfluous_schema_object_privileges[database]) > 0:
            all_superfluous_privileges_string = "{0}\n// ----- Schema Object Privileges\n{1};".format(
                all_superfluous_privileges_string,
                ";\n".join(all_superfluous_schema_object_privileges[database]).replace('GRANT ','REVOKE ').replace(' TO ROLE ',' FROM ROLE '))

        if verbose:
            print("For database {0}".format(database))
            print("  Missing schema privileges: {0}".format(all_missing_schema_privileges[database]))
            print("  Superfluous schema privileges: {0}".format(all_superfluous_schema_privileges[database]))
            print("  Missing schema object privileges: {0}".format(all_missing_schema_object_privileges[database]))
            print("  Superfluous schema object privileges: {0}".format(all_superfluous_schema_object_privileges[database]))

    all_missing_privileges_string = "{0}\nCOMMIT;\n".format(all_missing_privileges_string)
    all_superfluous_privileges_string = "{0}\nCOMMIT;\n".format(all_superfluous_privileges_string)

    if len(all_missing_schema_object_privileges.values()) == 0:
        print("No missing privileges, so no file output or execution required")
    else:
        if grant_statements_file:
            print("Writing GRANT statements to file {0}".format(grant_statements_file))
            grant_file = open(grant_statements_file,'w')
            grant_file.write(all_missing_privileges_string)
            grant_file.close()
        else:
            print("Executing GRANT statements in database")
            results = execute_snowflake_query(database, None, all_missing_privileges_string, verbose)
            for cursor in results:
                for row in cursor:
                    if 'Insufficient privileges' in row[0]:
                        raise ValueError(row[0])

    if len(all_superfluous_schema_object_privileges.values()) == 0:
        print("No superfluous privileges, so no file output or execution required")
    else:
        if revoke_statements_file:
            print("Writing REVOKE statements to file {0}".format(revoke_statements_file))
            grant_file = open(revoke_statements_file,'w')
            grant_file.write(all_superfluous_privileges_string)
            grant_file.close()
        else:
            print("Executing REVOKE statements in database")
            results = execute_snowflake_query(database, None, all_superfluous_privileges_string, verbose)
            for cursor in results:
                for row in cursor:
                    if 'Insufficient privileges' in row[0]:
                        raise ValueError(row[0])


    print("Completed successfully")


def execute_snowflake_query(snowflake_database, snowflake_schema, query, verbose):
    con = snowflake.connector.connect(
        user=os.environ["SNOWFLAKE_USER"],
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        role=os.environ["SNOWFLAKE_ROLE"],
        warehouse=os.environ["SNOWFLAKE_WAREHOUSE"],
        database=snowflake_database,
        schema=snowflake_schema,
        region=os.environ["SNOWFLAKE_REGION"],
        authenticator=os.environ["SNOWFLAKE_AUTHENTICATOR"],
        password=os.environ["SNOWSQL_PWD"]
    )
    if verbose:
        print("SQL query: %s" % query)
    try:
        return con.execute_string(query)
    finally:
        con.close()


def fetch_databases(verbose):
    query = "SHOW DATABASES"
    results = execute_snowflake_query('UTIL_DB', None, query, verbose)
    databases = []
    for cursor in results:
        for row in cursor:
            # Exclude any shared databases and UTIL_DB
            if row[4] == '' and row[1] != 'UTIL_DB':
                databases.append(row[1])
    return databases

def fetch_warehouses(verbose):
    query = "SHOW WAREHOUSES"
    results = execute_snowflake_query('UTIL_DB', None, query, verbose)
    warehouses = []
    for cursor in results:
        for row in cursor:
            warehouses.append(row[0])
    return warehouses


def fetch_roles(snowflake_database, snowflake_schema, verbose):
    query = "SHOW ROLES"
    results = execute_snowflake_query(snowflake_database, snowflake_schema, query, verbose)
    roles = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                roles.append(row[0])
    return roles

def generate_existing_table_and_view_privileges_sql(snowflake_database, verbose):
    query = """SELECT 'GRANT '||PRIVILEGE_TYPE||' ON '||REPLACE (tab.TABLE_TYPE,'BASE ','')||' \"'||OBJECT_CATALOG||'\".\"'||OBJECT_SCHEMA||'\".\"'||OBJECT_NAME||'\" TO ROLE \"'||GRANTEE||'\"' AS Privileges
    FROM {0}.INFORMATION_SCHEMA.OBJECT_PRIVILEGES priv
    JOIN {0}.INFORMATION_SCHEMA.TABLES tab ON priv.OBJECT_CATALOG=tab.TABLE_CATALOG and priv.OBJECT_SCHEMA=tab.TABLE_SCHEMA and priv.OBJECT_NAME=tab.TABLE_NAME
    WHERE OBJECT_TYPE = 'TABLE'
    AND PRIVILEGE_TYPE != 'OWNERSHIP'""".format(snowflake_database)
    results = execute_snowflake_query(snowflake_database, None, query, verbose)
    existing_privileges = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                existing_privileges.append(row[0])
    return existing_privileges


def generate_existing_schema_privileges_sql(snowflake_database, verbose):
    query = """SELECT 'GRANT '||PRIVILEGE_TYPE||' ON SCHEMA \"'||OBJECT_CATALOG||'\".\"'||OBJECT_NAME||'\" TO ROLE \"'||GRANTEE||'\"' AS Privileges
    FROM {0}.INFORMATION_SCHEMA.OBJECT_PRIVILEGES priv
    WHERE OBJECT_TYPE = 'SCHEMA'
    AND PRIVILEGE_TYPE != 'OWNERSHIP'""".format(snowflake_database)
    results = execute_snowflake_query(snowflake_database, None, query, verbose)
    existing_privileges = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                existing_privileges.append(row[0])
    return existing_privileges


def generate_existing_warehouse_privileges(warehouse_list, verbose):
    query=""
    for warehouse in warehouse_list:
        query = "{0}SHOW GRANTS ON WAREHOUSE {1};\n".format(query,warehouse)
    results = execute_snowflake_query('UTIL_DB', None, query, verbose)
    existing_privileges = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.' and row[4] == 'ROLE' and row[1] != 'OWNERSHIP':
                existing_privileges.append("GRANT {0} ON WAREHOUSE {1} TO ROLE {2}".format(row[1],row[3],row[5]))
    return existing_privileges

def generate_existing_database_privileges(database_list, verbose):
    query=""
    for database in database_list:
        query = "{0}SHOW GRANTS ON DATABASE {1};\n".format(query,database)
    results = execute_snowflake_query('UTIL_DB', None, query, verbose)
    existing_privileges = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.' and row[4] == 'ROLE' and row[1] != 'OWNERSHIP':
                existing_privileges.append("GRANT {0} ON DATABASE {1} TO ROLE {2}".format(row[1],row[3],row[5]))
    return existing_privileges


def generate_existing_account_object_privileges_sql(snowflake_database, verbose):
    query = """SELECT 'GRANT '||PRIVILEGE_TYPE||' ON '||OBJECT_TYPE||' \"'||OBJECT_CATALOG||'\".\"'||OBJECT_NAME||'\" TO ROLE \"'||GRANTEE||'\"' AS Privileges
    FROM {0}.INFORMATION_SCHEMA.OBJECT_PRIVILEGES priv
    WHERE OBJECT_TYPE IN ['DATABASE','WAREHOUSE','RESOURCE MONITOR']
    AND PRIVILEGE_TYPE != 'OWNERSHIP'""".format(snowflake_database)
    results = execute_snowflake_query(snowflake_database, None, query, verbose)
    existing_privileges = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                existing_privileges.append(row[0])
    return existing_privileges

def all_possible_table_and_view_privileges():
    return ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES']

def all_possible_table_and_view_privileges_clause():
    return (" union ".join(["select '{0}' as name".format(privileges) for privileges in all_possible_table_and_view_privileges()]))

def all_possible_schema_privileges():
    return ['MODIFY', 'MONITOR', 'USAGE', 'CREATE TABLE', 'CREATE TASK','CREATE EXTERNAL TABLE', 'CREATE VIEW', 'CREATE FILE FORMAT', 'CREATE STAGE', 'CREATE PIPE', 'CREATE SEQUENCE', 'CREATE FUNCTION']

def all_possible_schema_privileges_clause():
    return (" union ".join(["select '{0}' as name".format(privileges) for privileges in all_possible_schema_privileges()]))


def generate_grant_privileges_sql(database_name, grantee_role,schemas, tables, views, privileges, verbose):
    query = """USE DATABASE {0};
    SELECT 'GRANT '||privs.name||' ON TABLE \"{0}\".\"'||schms.SCHEMA_NAME||'\".\"'||tbls.TABLE_NAME||'\" TO ROLE \"{1}\"' AS Statement
    FROM INFORMATION_SCHEMA.SCHEMATA schms
    JOIN INFORMATION_SCHEMA.TABLES tbls ON (tbls.TABLE_SCHEMA = schms.SCHEMA_NAME)
    RIGHT OUTER JOIN ({5}) privs
    WHERE schms.SCHEMA_NAME LIKE '{2}'
    AND tbls.TABLE_NAME LIKE '{3}'
    AND tbls.TABLE_TYPE = 'BASE TABLE'
    AND schms.SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
    AND privs.name IN ({6})
    UNION
    SELECT 'GRANT '||privs.name||' ON VIEW \"{0}\".\"'||schms.SCHEMA_NAME||'\".\"'||vws.TABLE_NAME||'\" TO ROLE \"{1}\"' AS Statement
    FROM INFORMATION_SCHEMA.SCHEMATA schms
    JOIN INFORMATION_SCHEMA.VIEWS vws ON (vws.TABLE_SCHEMA = schms.SCHEMA_NAME)
    RIGHT OUTER JOIN (select 'SELECT' as name) privs
    WHERE schms.SCHEMA_NAME LIKE '{2}'
    AND vws.TABLE_NAME LIKE '{4}'
    AND schms.SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
    AND privs.name IN ({6})""".format(database_name,grantee_role,schemas, tables, views, all_possible_table_and_view_privileges_clause(),",".join(["'{0}'".format(privilege) for privilege in privileges]))
    results = execute_snowflake_query(database_name, None, query, verbose)
    grant_privileges_sql = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                grant_privileges_sql.append(row[0])
    return grant_privileges_sql

def generate_grant_schema_privileges_sql(database_name, grantee_role,schemas, privileges, verbose):
    query = """USE DATABASE {0};
    SELECT 'GRANT '||privs.name||' ON SCHEMA \"{0}\".\"'||schms.SCHEMA_NAME||'\" TO ROLE \"{1}\"' AS Statement
    FROM INFORMATION_SCHEMA.SCHEMATA schms
    RIGHT OUTER JOIN ({2}) privs
    WHERE schms.SCHEMA_NAME LIKE '{3}'
    AND schms.SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
    AND privs.name IN ({4})""".format(database_name,grantee_role, all_possible_schema_privileges_clause(),schemas,",".join(["'{0}'".format(privilege) for privilege in privileges]))
    results = execute_snowflake_query(database_name, None, query, verbose)
    grant_privileges_sql = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                grant_privileges_sql.append(row[0])
    return grant_privileges_sql


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Apply a set of permission rules to a Snowflake account")
    parser.add_argument('-a', '--snowflake-account', type=str, help='The name of the environment (e.g. dev,test,prod)',
                        required=True)
    parser.add_argument('-u', '--snowflake-user', type=str, help='The name of the snowflake user (e.g. deployer)',
                        required=True)
    parser.add_argument('-r', '--snowflake-role', type=str, help='The name of the role to use (e.g. DEPLOYER_ROLE)',
                        required=True)
    parser.add_argument('-w', '--snowflake-warehouse', type=str,
                        help='The name of the warehouse to use (e.g. DEPLOYER_WAREHOUSE)', required=True)
    parser.add_argument('--snowflake-region', type=str, help='The name of the snowflake region (e.g. ap-southeast-2)',
                        required=True)
    parser.add_argument('-p', '--permissions-file', default="Permissions.json", type=str,
                        help='The file containing the permission definitions')
    parser.add_argument('-g', '--grant-statements-file', default=None, type=str,
                        help='The name of a file to output the GRANT statements to, instead of applying them automatically')
    parser.add_argument('-e', '--revoke-statements-file', default=None, type=str,
                        help='The name of a file to output the REVOKE statements to. instead of applying them automatically')
    parser.add_argument('-v', '--verbose', type=bool, default=False)
    args = parser.parse_args()


apply_permissions(args.snowflake_account, args.snowflake_user, args.snowflake_role, args.snowflake_warehouse,
                  args.snowflake_region, args.permissions_file,args.grant_statements_file,args.revoke_statements_file, args.verbose)
