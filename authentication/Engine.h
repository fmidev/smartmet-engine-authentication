#pragma once

#include "Config.h"
#include <spine/SmartMetEngine.h>
#include <memory>
#include <string>
#include <vector>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
class Engine final : public SmartMet::Spine::SmartMetEngine
{
 public:
  explicit Engine(const char* theConfigFile);
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
  std::unique_ptr<Impl> impl;
  Impl& get_impl() const;
};

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet
