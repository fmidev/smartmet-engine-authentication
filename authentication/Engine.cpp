#include "Engine.h"
#include <macgyver/AnsiEscapeCodes.h>
#include <macgyver/AsyncTask.h>
#include <macgyver/Exception.h>
#include <macgyver/PostgreSQLConnection.h>
#include <macgyver/StringConversion.h>
#include <macgyver/TypeName.h>
#include <spine/Convenience.h>
#include <spine/Reactor.h>
#include <stdexcept>
#include <utility>

namespace SmartMet
{
namespace Engine
{
namespace Authentication
{
const std::string WILDCARD_IDENTIFIER = "*";

// Enum to signify access resolution status
enum class AccessStatus
{
  WILDCARD_GRANT,
  GRANT,
  DENY,
  UNKNOWN_APIKEY
};

// Token class
// Describes a singe authorization token, which has zero or more token values
class Token
{
 public:
  explicit Token(std::string name) : itsName(std::move(name)) {}

  bool addValue(const std::string& value) const;  // Constness here is hack, because std::set only
                                                  // has const_iterators

  void deleteValue(const std::string& value);

  bool hasValue(const std::string& value) const;

  bool operator<(const Token& other) const;

  bool operator==(const Token& other) const;

  bool operator!=(const Token& other) const;

 private:
  std::string itsName;

  mutable std::set<std::string> itsValues;  // Hack, because std::set allows only const_iterators
};

bool Token::addValue(const std::string& value) const
{
  return itsValues.insert(value).second;
}
void Token::deleteValue(const std::string& value)
{
  itsValues.erase(value);
}
bool Token::hasValue(const std::string& value) const
{
  return (itsValues.find(value) != itsValues.end());
}

bool Token::operator<(const Token& other) const
{
  return itsName < other.itsName;
}
bool Token::operator==(const Token& other) const
{
  return itsName == other.itsName;
}
bool Token::operator!=(const Token& other) const
{
  return itsName != other.itsName;
}
// Type to signify that all token values are valid
struct WildCard
{
};

// Service class
// Tracks apikey-> token value relationships for a single service definition
// This object can be queried if a given apikey has access to a number of token values
class Service
{
 public:
  explicit Service(std::string name) : itsName(std::move(name)) {}

  bool addToken(const std::string& apikey, const Token& token);

  bool addTokenSet(const std::string& apikey, const std::set<Token>& tokens);

  bool addWildCard(const std::string& apikey);

  AccessStatus resolveAccess(const std::string& apikey,
                             const std::string& value,
                             bool explicitGrantOnly = false) const;

 private:
  std::string itsName;

  std::set<std::string> itsWildCardApikeys;

  // Apikey -> one or more token definitions
  std::map<std::string, std::set<Token>> itsTokenApikeyMapping;
};

bool Service::addToken(const std::string& apikey, const Token& token)
{
  try
  {
    auto it = itsTokenApikeyMapping.find(apikey);

    if (it == itsTokenApikeyMapping.end())
    {
      // No such apikey yet
      return itsTokenApikeyMapping.insert(std::make_pair(apikey, std::set<Token>{token})).second;
    }

    auto& tokenSet = it->second;
    return tokenSet.insert(token).second;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

bool Service::addTokenSet(const std::string& apikey, const std::set<Token>& tokens)
{
  try
  {
    return itsTokenApikeyMapping.insert(std::make_pair(apikey, tokens)).second;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

bool Service::addWildCard(const std::string& apikey)
{
  try
  {
    return itsWildCardApikeys.insert(apikey).second;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

AccessStatus Service::resolveAccess(const std::string& apikey,
                                    const std::string& value,
                                    bool explicitGrantOnly) const
{
  try
  {
    // First check if this apikey has "wildcard" definition, it means universal access
    if (!explicitGrantOnly && (itsWildCardApikeys.find(apikey) != itsWildCardApikeys.end()))
      return AccessStatus::WILDCARD_GRANT;

    // Next check if value is found in token definitions for this apikey
    auto it = itsTokenApikeyMapping.find(apikey);

    if (it == itsTokenApikeyMapping.end())
    {
      // No such apikey defined for this service.
      return explicitGrantOnly ? AccessStatus::DENY : AccessStatus::UNKNOWN_APIKEY;
    }

    const auto& tokens = it->second;

    // See if value is defined in one of the token sets:
    for (const auto& token : tokens)
    {
      if (token.hasValue(value))
        return AccessStatus::GRANT;
    }

    return AccessStatus::DENY;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

class AuthEngine final : public Engine
{
public:
  explicit AuthEngine(const char* theConfigFile);

  ~AuthEngine() = default;

  AuthEngine(const AuthEngine& other) = delete;
  AuthEngine& operator=(const AuthEngine& other) = delete;
  AuthEngine(AuthEngine&& other) = delete;
  AuthEngine& operator=(AuthEngine&& other) = delete;

  void init() override;
  void shutdown() override;

  bool isEnabled() const override
  {
    return true;  // This implementation is for enabled engine
  }

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

  std::unique_ptr<Fmi::AsyncTask> itsUpdateTask;

  int itsActiveThreadCount = 0;
};

AuthEngine::AuthEngine(const char* theConfigFile) : itsConfig(theConfigFile) {}

bool AuthEngine::authorize(const std::string& apikey,
                           const std::string& tokenvalue,
                           const std::string& service,
                           bool explicitGrantOnly) const
{
  try
  {
    SmartMet::Spine::ReadLock lock(itsMutex);
    auto it = itsServices.find(service);
    if (it != itsServices.end())
    {
      AccessStatus value_status = it->second.resolveAccess(apikey, tokenvalue, explicitGrantOnly);
      switch (value_status)
      {
        case AccessStatus::UNKNOWN_APIKEY:
          // Unknown apikey for this aservice
          // Default access policy is "allow", unknown apikey is let through
          return itsConfig.defaultAccessAllow;
        case AccessStatus::DENY:
          return false;
        case AccessStatus::GRANT:
        case AccessStatus::WILDCARD_GRANT:
        default:  // Dummy case, for compiler
          return true;
      }
    }
    else  // Unkown service, either there is a plugin programming error or no access tokens are
          // defined for this service
      return !explicitGrantOnly;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

bool AuthEngine::authorize(const std::string& apikey,
                           const std::vector<std::string>& tokenvalues,
                           const std::string& service) const
{
  try
  {
    SmartMet::Spine::ReadLock lock(itsMutex);

    auto it = itsServices.find(service);
    if (it == itsServices.end())
      return true;  // Unknown service, let through

    for (const std::string& value : tokenvalues)
    {
      // Let through if all tokens are valid
      AccessStatus value_status = it->second.resolveAccess(apikey, value);

      switch (value_status)
      {
        case AccessStatus::UNKNOWN_APIKEY:
        {
          // Unknown apikey for this aservice
          // Default access policy is "allow", unknown apikey is let through
          return itsConfig.defaultAccessAllow;
        }
        case AccessStatus::DENY:
        {
          // Disallowed value encountered, deny access;
          return false;
        }
        case AccessStatus::GRANT:
        {
          // Allowed value, continue to the next
          continue;
        }
        case AccessStatus::WILDCARD_GRANT:
        {
          // This apikey has universal access, no reason to loop through all token values
          return true;
        }
      }
    }

    // All tokens valid
    return true;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

void AuthEngine::init()
{
  try
  {
    rebuildMappings();

    itsUpdateTask.reset(
        new Fmi::AsyncTask("Authentication engine update task", [this]() { rebuildUpdateLoop(); }));
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

// ----------------------------------------------------------------------
/*!
 * \brief Shutdown the engine
 */
// ----------------------------------------------------------------------

void AuthEngine::shutdown()
{
  try
  {
    std::cout << "  -- Shutdown requested (authentication engine)\n";

    if (itsUpdateTask)
    {
      itsUpdateTask->cancel();
      itsUpdateTask->wait();
      itsUpdateTask.reset();
    }
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

void AuthEngine::rebuildUpdateLoop()
{
  try
  {
    itsActiveThreadCount++;
    while (!Spine::Reactor::isShuttingDown())
    {
      try
      {
        rebuildMappings();
      }
      catch (...)
      {
        Fmi::Exception exception(BCP, "Database exception!", nullptr);
        exception.printError();
      }

      for (int i = 0; (!Spine::Reactor::isShuttingDown() && i < itsConfig.updateIntervalSeconds);
           i++)
        boost::this_thread::sleep_for(boost::chrono::milliseconds(1000));
    }
    itsActiveThreadCount--;
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

void AuthEngine::rebuildMappings()
{
  using namespace Fmi::Database;
  try
  {
    PostgreSQLConnectionOptions opt;
    opt.host = itsConfig.dBHost;
    opt.port = itsConfig.port;
    opt.database = itsConfig.database;
    opt.username = itsConfig.user;
    opt.password = itsConfig.password;

    PostgreSQLConnection conn(opt);

    std::string query;
    pqxx::result res;

    auto transaction = conn.transaction();

    // Get token definitions
    query =
        "SELECT service,token,value from " + itsConfig.schema + "." + itsConfig.tokenTable + ";";
    res = transaction->execute(query);

    std::map<std::string, Service> newServices;
    std::map<std::string, std::set<Token>> newTokens;

    // Construct token objects
    for (auto row : res)
    {
      std::string value;
      std::string service;
      std::string token;

      // Indexing like so should be safe, database columns are 'not null'
      row[0].to(service);
      row[1].to(token);
      row[2].to(value);

      std::set<Token> tokens;
      auto it = newTokens.insert(std::make_pair(service, tokens)).first;

      Token thisToken(token);
      auto tokenIt = it->second.insert(thisToken).first;

      tokenIt->addValue(value);
    }

    // Construct Service objects
    query =
        "SELECT apikey,service,token from " + itsConfig.schema + "." + itsConfig.authTable + ";";
    res = transaction->execute(query);

    for (auto row : res)
    {
      std::string apikey;
      std::string service;
      std::string token;

      // Indexing like so should be safe, database columns are 'not null'
      row[0].to(apikey);
      row[1].to(service);
      row[2].to(token);

      // Check errors here!

      Service newService(service);
      auto it = newServices.insert(std::make_pair(service, newService)).first;

      // Check if token name is the wildcard definition
      if (token == WILDCARD_IDENTIFIER)
      {
        it->second.addWildCard(apikey);
        continue;
      }

      // Get defined tokens
      auto tokenSetIt = newTokens.find(service);
      if (tokenSetIt != newTokens.end())
      {
        auto tokenIt = tokenSetIt->second.find(
            Token(token));  // Find the token object for this particular token name
        if (tokenIt == tokenSetIt->second.end())
          continue;                             // This is misconfiguration in the
                                                // database
        it->second.addToken(apikey, *tokenIt);  // This could be a pointer type to save
                                                // space
      }
    }

    SmartMet::Spine::WriteLock lock(itsMutex);

    std::swap(newServices, itsServices);
  }
  catch (...)
  {
    throw Fmi::Exception::Trace(BCP, "Operation failed!");
  }
}

}  // namespace Authentication
}  // namespace Engine
}  // namespace SmartMet

// DYNAMIC MODULE CREATION TOOLS

extern "C" void* engine_class_creator(const char* configfile, void* /* user_data */)
{
  if (!configfile || *configfile == 0)
  {
    std::cout << SmartMet::Spine::log_time_str() << ' ' << ANSI_FG_RED << "Authentication engine"
              << ": configuration file not specified or its name is empty string: "
              << "engine disabled." << ANSI_FG_DEFAULT << std::endl;
    return new SmartMet::Engine::Authentication::Engine;
  }

  SmartMet::Spine::ConfigBase cfg(configfile);
  const bool disabled = cfg.get_optional_config_param<bool>("disabled", false);
  if (disabled)
  {
    std::cout << SmartMet::Spine::log_time_str() << ' ' << ANSI_FG_RED
              << "Authentication engine is disabled" << ANSI_RESET << std::endl;
    return new SmartMet::Engine::Authentication::Engine;
  }
  else
  {
    return new SmartMet::Engine::Authentication::AuthEngine(configfile);
  }
}

extern "C" const char* engine_name()
{
  return "Authentication";
}
