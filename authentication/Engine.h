#pragma once

#include "Config.h"
#include <memory>
#include <spine/SmartMetEngine.h>
#include <string>
#include <vector>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
class Service;

class Engine final : public SmartMet::Spine::SmartMetEngine
{
 public:
  Engine(const char* theConfigFile);
  ~Engine() override = default;

  Engine(const Engine& other) = delete;
  Engine& operator=(const Engine& other) = delete;
  Engine(Engine&& other) = delete;
  Engine& operator=(Engine&& other) = delete;

  // Query if given apikey has access to a number of token values for a given service
  bool authorize(const std::string& apikey,
                 const std::vector<std::string>& tokenvalues,
                 const std::string& service) const;

  // Authorize a single value for given service
  bool authorize(const std::string& apikey,
                 const std::string& tokenvalue,
                 const std::string& service,
                 bool explicitGrantOnly = false) const;

 protected:
  void init() override;
  void shutdown() override;

 private:
  class Impl;
  enum class AccessStatus;
  class Token;
  struct WildCard;
  class Service;

 private:
  Impl& get_impl() const;

 private:
  std::unique_ptr<Impl> impl;
};

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
