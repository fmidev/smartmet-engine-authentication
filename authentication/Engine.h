#pragma once

#include <spine/SmartMetEngine.h>
#include <spine/Thread.h>

#include <string>
#include <vector>
#include <map>
#include <set>

#include "Config.h"

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
  ~Engine();

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

  std::unique_ptr<boost::thread> itsUpdateThread;

  int itsActiveThreadCount;

 protected:
  virtual void init();
  void shutdown();
};

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
