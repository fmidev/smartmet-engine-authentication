#include "Engine.h"
#include <regression/tframe.h>

#include <spine/Options.h>
#include <spine/Reactor.h>

using namespace std;

std::shared_ptr<SmartMet::Engine::Authentication::Engine> authengine;
std::string apikey = "testkey";
std::string apikey2 = "testkey2";
std::string apikey_wildcard = "testkey_wildcard";

namespace Tests
{
// ----------------------------------------------------------------------

void access_single()
{
  bool has_access;

  has_access = authengine->authorize(apikey, "value1", "testservice");
  if (!has_access)
    TEST_FAILED("No access to 'value1' token value");

  has_access = authengine->authorize(apikey, "value2", "testservice");
  if (!has_access)
    TEST_FAILED("No access to 'value2' token value");

  has_access = authengine->authorize(apikey, "value3", "testservice");
  if (!has_access)
    TEST_FAILED("No access to 'value3' token value");

  has_access = authengine->authorize(apikey2, "value3", "testservice");
  if (!has_access)
    TEST_FAILED("No access to 'value3' token value");

  has_access = authengine->authorize(apikey2, "value1", "testservice2");
  if (!has_access)
    TEST_FAILED("No access to 'value1' token value for 'testservice2'");

  has_access = authengine->authorize(apikey2, "value1", "testservice");
  if (has_access)
    TEST_FAILED("Incorrectly granted access to 'value1' token value");

  has_access = authengine->authorize(apikey2, "value2", "testservice2");
  if (has_access)
    TEST_FAILED("Incorrectly granted access to 'value1' token value");

  TEST_PASSED();
}

void access_wildcard()
{
  std::vector<std::string> values = {"value1", "value2", "value3"};

  bool has_access;

  for (const auto &value : values)
  {
    has_access = authengine->authorize(apikey_wildcard, value, "testservice");
    if (!has_access)
      TEST_FAILED("No access with wildcard apikey to value '" + value + "'");
  }

  has_access = authengine->authorize(apikey_wildcard, values, "testservice");
  if (!has_access)
    TEST_FAILED("No access with wildcard apikey to valueset 'value1,value2,value3'");

  TEST_PASSED();
}

void access_multiple()
{
  std::vector<std::string> values = {"value1", "value2", "value3"};

  bool has_access;

  has_access = authengine->authorize(apikey, values, "testservice");
  if (!has_access)
    TEST_FAILED("No access to valueset 'value1,value2,value3'");

  has_access = authengine->authorize(apikey2, values, "testservice");
  if (has_access)
    TEST_FAILED("Incorrectly granted access to valueset 'value1,value2,value3'");

  TEST_PASSED();
}

void unknown_apikey()
{
  bool has_access;

  has_access = authengine->authorize("foobar", "value1", "testservice");
  if (has_access)
    TEST_FAILED("Unknown 'foobar_apikey' should not have access (default policy is DENY)");

  TEST_PASSED();
}

void access_denied()
{
  std::vector<std::string> values = {"value1", "value2", "value4"};  // value4 not found in tokens

  bool has_access;

  has_access = authengine->authorize(apikey, values, "testservice");
  if (has_access)
    TEST_FAILED("Incorrectly has access to 'value4' token value");

  has_access = authengine->authorize(apikey, "value4", "testservice");
  if (has_access)
    TEST_FAILED("Incorrectly has access to 'value4' token value");

  has_access = authengine->authorize(apikey, "value1", "nonexistent_service");
  if (!has_access)
    TEST_FAILED("Incorrectly no access to 'nonexistent_service' service");

  TEST_PASSED();
}

// Test driver
class tests : public tframe::tests
{
  // Overridden message separator
  virtual const char *error_message_prefix() const { return "\n\t"; }
  // Main test suite
  void test()
  {
    TEST(access_single);
    TEST(access_multiple);
    TEST(access_denied);
    TEST(access_wildcard);
    TEST(unknown_apikey);
  }

};  // class tests

}  // namespace Tests

int main(void)
{
  SmartMet::Spine::Options opts;
  opts.configfile = "cnf/reactor.conf";
  opts.parseConfig();

  SmartMet::Spine::Reactor reactor(opts);
  reactor.init();
  authengine = reactor.getEngine<SmartMet::Engine::Authentication::Engine>("Authentication", NULL);

  cout << endl << "Engine tester" << endl << "=============" << endl;
  Tests::tests t;
  auto result = t.run();
  authengine.reset();
  reactor.shutdown();
  return result;
}
