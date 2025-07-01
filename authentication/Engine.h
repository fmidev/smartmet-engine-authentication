#pragma once

#include "Config.h"
#include <spine/SmartMetEngine.h>
#include <macgyver/Exception.h>
#include <memory>
#include <string>
#include <vector>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
class Engine : public SmartMet::Spine::SmartMetEngine
{
 public:
  Engine() {};
  ~Engine() override = default;

  Engine(const Engine& other) = delete;
  Engine& operator=(const Engine& other) = delete;
  Engine(Engine&& other) = delete;
  Engine& operator=(Engine&& other) = delete;

  virtual bool isEnabled() const
  {
    return false;  // Default dummy implementation for disabled engine
  }

  // Query if given apikey has access to a number of token values for a given service
  virtual bool authorize(const std::string& apikey,
                 const std::vector<std::string>& tokenvalues,
                 const std::string& service) const
  {
    (void)apikey;
    (void)tokenvalues;
    (void)service;
    throw Fmi::Exception(BCP, "Not implemented");
  }

  // Authorize a single value for given service
  virtual bool authorize(const std::string& apikey,
                 const std::string& tokenvalue,
                 const std::string& service,
                 bool explicitGrantOnly = false) const
  {
    (void)apikey;
    (void)tokenvalue;
    (void)service;
    (void)explicitGrantOnly;
    throw Fmi::Exception(BCP, "Not implemented");
  }
protected:
  void init() override {}
  void shutdown() override {}
};

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
