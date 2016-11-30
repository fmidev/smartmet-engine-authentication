#include "Config.h"
#include <spine/Exception.h>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
Config::Config(const std::string& configFile) : ConfigBase(configFile)
{
  try
  {
    dBHost = get_mandatory_config_param<std::string>("database.host");
    port = get_mandatory_config_param<unsigned int>("database.port");
    database = get_mandatory_config_param<std::string>("database.database");
    schema = get_mandatory_config_param<std::string>("database.schema");
    user = get_mandatory_config_param<std::string>("database.username");
    password = get_mandatory_config_param<std::string>("database.password");
    authTable = get_mandatory_config_param<std::string>("database.auth_table");
    tokenTable = get_mandatory_config_param<std::string>("database.token_table");
    updateIntervalSeconds = get_mandatory_config_param<int>("database.update_interval_seconds");

    defaultAccessAllow = get_mandatory_config_param<bool>("default_access_is_allow");
  }
  catch (...)
  {
    throw SmartMet::Spine::Exception(BCP, "Operation failed!", NULL);
  }
}

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
