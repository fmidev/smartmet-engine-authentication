#pragma once

#include <spine/ConfigBase.h>

#include <string>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
class Config : public SmartMet::Spine::ConfigBase
{
 public:
  Config(const std::string& configFile);

  std::string dBHost;

  unsigned int port;

  std::string database;

  std::string schema;

  std::string user;

  std::string password;

  std::string authTable;

  std::string tokenTable;

  int updateIntervalSeconds;

  // Unknown apikey access behaviour
  bool defaultAccessAllow;
};

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
