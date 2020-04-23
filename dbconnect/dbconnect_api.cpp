#include <mysql-cppconn-8/mysqlx/xdevapi.h>
#include "dbconnect_api.h"
#include <fstream>
#include <sstream>

static std::string domain;
static std::string username;
static std::string password;

int up_init()
{
    std::ifstream fin("./database_info.json");
    std::stringstream buffer;
    buffer << fin.rdbuf();
    fin.close();
    std::string file_content(buffer.str());

    std::string json_error;
    json11::Json json_obj;
    json_obj = json11::Json().parse(file_content, json_error, json11::STANDARD);
    domain = json_obj["domain"].string_value();
    username = json_obj["username"].string_value();
    password = json_obj["password"].string_value();
    return 1;
}

/**
 * @brief 通过被回调进行数据库写入操作
 * 
 * 
 */
void db_write(std::string bytes)
{
    if (DBWRITE_RAW_DATA)
    {
        try
        {
            static int up_init_stat = up_init();
            mysqlx::Session sess = mysqlx::Session(domain, 33060, username, password);
            mysqlx::Schema db = sess.getSchema("net_sharpknife", true);
            mysqlx::Table tb = db.getTable("network_flow", true);
            tb.insert("flow_content").values(bytes).execute();
        }
        catch (const std::exception &e)
        {
            SN_Debug("Exception : %s\n", e.what());
            exit(0);
        }
    }
}