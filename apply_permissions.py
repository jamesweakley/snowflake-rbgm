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

    # for each database, gather all existing grant statements
    all_defined_privileges={}
    existing_database_grants={}
    for database in all_databases:
        existing_database_grants[database] = generate_existing_privileges_sql(database, verbose)
        all_defined_privileges[database]=set()
        if verbose:
            print("Statements to grant existing privileges in database '{0}': {1}".format(database,existing_database_grants[database]))


    # iterate through the privilege rules defined in the file.
    # for each rule, generate all grant statements required to bring it into effect,
    # storing them grouped by database. Using sets will eliminate any rule overlap and prevent duplicate grant statements
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

            all_defined_privileges[database]=all_defined_privileges[database].union(grant_privileges_sql_statements)

    # for each database, produce lists of both missing and superfluous statements (the latter being REVOKEs),
    # such that running them all should bring the database in sync with the rules file
    all_missing_privileges={}
    all_superfluous_privileges={}

    all_missing_privileges_string = "BEGIN TRANSACTION;\n"
    all_superfluous_privileges_string = "BEGIN TRANSACTION;\n"
    for database in all_databases:
        all_missing_privileges[database] = (list(set(all_defined_privileges[database]) - set(existing_database_grants[database])))
        all_superfluous_privileges[database] = list(set(existing_database_grants[database]) - set(all_defined_privileges[database]))

        all_missing_privileges_string = "{0}\n// ------------ Database {1}\n{2}".format(
            all_missing_privileges_string,
            database,
            ";\n".join(all_missing_privileges[database]))

        if len(all_missing_privileges[database]) > 0:
            all_missing_privileges_string = "{0};\n".format(all_missing_privileges_string)

        all_superfluous_privileges_string = "{0}\n// ------------ Database {1}\n{2}\n".format(
            all_superfluous_privileges_string,
            database,
            ";\n".join(all_superfluous_privileges[database]).replace('GRANT ','REVOKE ').replace(' TO ROLE ',' FROM ROLE '))

        if len(all_superfluous_privileges[database]) > 0:
            all_superfluous_privileges_string = "{0};\n".format(all_superfluous_privileges_string)

        if verbose:
            print("For database {0}".format(database))
            print("  Missing privileges: {0}".format(all_missing_privileges[database]))
            print("  Superfluous privileges: {0}".format(all_superfluous_privileges[database]))

    all_missing_privileges_string = "{0}\nCOMMIT;\n".format(all_missing_privileges_string)
    all_superfluous_privileges_string = "{0}\nCOMMIT;\n".format(all_superfluous_privileges_string)

    if len(all_missing_privileges.values()) == 0:
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

    if len(all_superfluous_privileges.values()) == 0:
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
    query = "SELECT DATABASE_NAME FROM UTIL_DB.INFORMATION_SCHEMA.DATABASES dbs WHERE dbs.DATABASE_NAME NOT IN ('UTIL_DB')"
    results = execute_snowflake_query('UTIL_DB', None, query, verbose)
    databases = []
    for cursor in results:
        for row in cursor:
            databases.append(row[0])
    return databases

def fetch_roles(snowflake_database, snowflake_schema, verbose):
    query = "SHOW ROLES"
    results = execute_snowflake_query(snowflake_database, snowflake_schema, query, verbose)
    roles = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                roles.append(row[0])
    return roles

def generate_existing_privileges_sql(snowflake_database, verbose):
    query = """SELECT 'GRANT '||PRIVILEGE_TYPE||' ON '||REPLACE (tab.TABLE_TYPE,'BASE ','')||' '||OBJECT_CATALOG||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME||' TO ROLE "'||GRANTEE||'"' AS Privileges
    FROM {0}.INFORMATION_SCHEMA.OBJECT_PRIVILEGES priv
    JOIN {0}.INFORMATION_SCHEMA.TABLES tab ON priv.OBJECT_CATALOG=tab.TABLE_CATALOG and priv.OBJECT_SCHEMA=tab.TABLE_SCHEMA and priv.OBJECT_NAME=tab.TABLE_NAME
    WHERE OBJECT_CATALOG IS NOT NULL
    AND PRIVILEGE_TYPE != 'OWNERSHIP'""".format(snowflake_database)
    results = execute_snowflake_query(snowflake_database, None, query, verbose)
    existing_privileges = []
    for cursor in results:
        for row in cursor:
            if row[0] != 'Statement executed successfully.':
                existing_privileges.append(row[0])
    return existing_privileges

def all_possible_privileges():
    return ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES']

def all_possible_privileges_clause():
    return (" union ".join(["select '{0}' as name".format(privileges) for privileges in all_possible_privileges()]))

def generate_grant_privileges_sql(database_name, grantee_role,schemas, tables, views, privileges, verbose):
    query = """USE DATABASE {0};
    SELECT 'GRANT '||privs.name||' ON TABLE {0}.'||schms.SCHEMA_NAME||'.'||tbls.TABLE_NAME||' TO ROLE \"{1}\"' AS Statement
    FROM INFORMATION_SCHEMA.SCHEMATA schms
    JOIN INFORMATION_SCHEMA.TABLES tbls ON (tbls.TABLE_SCHEMA = schms.SCHEMA_NAME)
    RIGHT OUTER JOIN ({5}) privs
    WHERE schms.SCHEMA_NAME LIKE '{2}'
    AND tbls.TABLE_NAME LIKE '{3}'
    AND schms.SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
    AND privs.name IN ({6})
    UNION
    SELECT 'GRANT '||privs.name||' ON VIEW {0}.'||schms.SCHEMA_NAME||'.'||vws.TABLE_NAME||' TO ROLE \"{1}\"' AS Statement
    FROM INFORMATION_SCHEMA.SCHEMATA schms
    JOIN INFORMATION_SCHEMA.VIEWS vws ON (vws.TABLE_SCHEMA = schms.SCHEMA_NAME)
    RIGHT OUTER JOIN (select 'SELECT' as name) privs
    WHERE schms.SCHEMA_NAME LIKE '{2}'
    AND vws.TABLE_NAME LIKE '{4}'
    AND schms.SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
    AND privs.name IN ({6})""".format(database_name,grantee_role,schemas, tables, views, all_possible_privileges_clause(),",".join(["'{0}'".format(privilege) for privilege in privileges]))
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
