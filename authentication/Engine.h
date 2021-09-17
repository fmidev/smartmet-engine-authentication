#pragma once

#include "Config.h"
#include <boost/move/unique_ptr.hpp>
#include <spine/SmartMetEngine.h>
#include <spine/Thread.h>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
class Service;

class Engine : public SmartMet::Spine::SmartMetEngine
{
 public:
  Engine(const char* theConfigFile);
  ~Engine() override;

  // Query if given apikey has access to a number of token values for a given service
  bool authorize(const std::string& apikey,
                 const std::vector<std::string>& tokenvalues,
                 const std::string& service) const;

  // Authorize a single value for given service
  bool authorize(const std::string& apikey,
                 const std::string& tokenvalue,
                 const std::string& service,
                 bool explicitGrantOnly = false) const;

 private:
  // Rebuilds apikey service mappings
  void rebuildMappings();

  // Updates mappings in the background
  void rebuildUpdateLoop();

  Config itsConfig;

  // Service name -> Service definition
  std::map<std::string, Service> itsServices;

  mutable SmartMet::Spine::MutexType itsMutex;

  boost::movelib::unique_ptr<boost::thread> itsUpdateThread;

  int itsActiveThreadCount;

 protected:
  void init() override;
  void shutdown() override;
};

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
