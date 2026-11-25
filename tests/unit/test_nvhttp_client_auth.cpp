/**
 * @file tests/unit/test_nvhttp_client_auth.cpp
 * @brief Test exact paired-client certificate authorization and persistence.
 */

// test includes
#include "../certificate_test_utils.h"
#include "../tests_common.h"

// standard includes
#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <thread>
#include <type_traits>
#include <vector>

// lib includes
#include <Simple-Web-Server/client_https.hpp>

// local includes
#include <src/config.h>
#include <src/nvhttp.h>

namespace fs = std::filesystem;

static_assert(std::is_same_v<decltype(&nvhttp::pin), bool (*)(std::string_view, const std::string &, std::string)>);

/**
 * @brief Isolate paired-client authorization tests from the user's Sunshine state.
 */
class ClientAuthorizationTest: public BaseTest {
protected:
  /**
   * @brief Redirect persisted client state to the test build directory.
   */
  void SetUp() override {
    BaseTest::SetUp();
    original_state_file = config::nvhttp.file_state;
    original_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
    state_file = fs::path {SUNSHINE_TEST_BIN_DIR} / "client_authorization_state.json";

    config::nvhttp.file_state = state_file.string();
    config::sunshine.flags[config::flag::FRESH_STATE] = false;
    nvhttp::test_support::reset_client_state();

    std::error_code remove_error;
    fs::remove(state_file, remove_error);
  }

  /**
   * @brief Remove test state and restore the caller's configuration.
   */
  void TearDown() override {
    nvhttp::test_support::reset_client_state();
    std::error_code remove_error;
    fs::remove(state_file, remove_error);

    config::nvhttp.file_state = original_state_file;
    config::sunshine.flags[config::flag::FRESH_STATE] = original_fresh_state;
    BaseTest::TearDown();
  }

private:
  fs::path state_file;  ///< Task-specific persisted state fixture.
  std::string original_state_file;  ///< State-file setting restored after each test.
  bool original_fresh_state;  ///< Fresh-state flag restored after each test.
};

TEST_F(ClientAuthorizationTest, CanonicalIdentityFailsClosedAndTracksEnableState) {
  const auto paired_credentials = test_utils::certificates::generate_ca_credentials();
  const auto crlf_certificate = test_utils::certificates::to_crlf_pem(paired_credentials.x509);
  const auto unknown_credentials = crypto::gen_creds("Sunshine Unknown Client", 2048);
  const auto uuid = nvhttp::test_support::add_client("paired", crlf_certificate, true);

  EXPECT_TRUE(nvhttp::test_support::add_client("invalid", "not a certificate", true).empty());
  ASSERT_FALSE(uuid.empty());
  EXPECT_EQ(nvhttp::get_cert_by_uuid(uuid), paired_credentials.x509);
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(crlf_certificate));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(unknown_credentials.x509));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate("not a certificate"));

  ASSERT_TRUE(nvhttp::set_client_enabled(uuid, false));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
  ASSERT_TRUE(nvhttp::set_client_enabled(uuid, true));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
}

TEST_F(ClientAuthorizationTest, DerivedLeafDoesNotInheritPairedAuthorization) {
  const auto paired_credentials = test_utils::certificates::generate_ca_credentials();
  const auto derived_credentials = test_utils::certificates::generate_derived_leaf(paired_credentials);
  const auto uuid = nvhttp::test_support::add_client("paired issuer", paired_credentials.x509, true);

  ASSERT_FALSE(uuid.empty());
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(derived_credentials.x509));

  ASSERT_TRUE(nvhttp::set_client_enabled(uuid, false));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(derived_credentials.x509));
}

TEST_F(ClientAuthorizationTest, MultipleClientsPersistAndUnpairIndependently) {
  const auto enabled_credentials = test_utils::certificates::generate_ca_credentials("Sunshine Enabled Client");
  const auto disabled_credentials = crypto::gen_creds("Sunshine Disabled Client", 2048);
  const auto expired_credentials = test_utils::certificates::expire_credentials(
    test_utils::certificates::generate_ca_credentials("Sunshine Expired Client")
  );

  const auto enabled_uuid = nvhttp::test_support::add_client("enabled", enabled_credentials.x509, true);
  const auto disabled_uuid = nvhttp::test_support::add_client("disabled", disabled_credentials.x509, false);
  const auto expired_uuid = nvhttp::test_support::add_client("expired", expired_credentials.x509, true);
  ASSERT_FALSE(enabled_uuid.empty());
  ASSERT_FALSE(disabled_uuid.empty());
  ASSERT_FALSE(expired_uuid.empty());
  EXPECT_EQ(nvhttp::get_all_clients().size(), 3);

  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(enabled_credentials.x509));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(disabled_credentials.x509));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(expired_credentials.x509));

  nvhttp::test_support::reset_client_state();
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(enabled_credentials.x509));
  nvhttp::test_support::reload_client_state();

  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(enabled_credentials.x509));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(disabled_credentials.x509));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(expired_credentials.x509));

  ASSERT_TRUE(nvhttp::set_client_enabled(disabled_uuid, true));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(disabled_credentials.x509));
  ASSERT_TRUE(nvhttp::unpair_client(enabled_uuid));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(enabled_credentials.x509));

  nvhttp::erase_all_clients();
  nvhttp::test_support::reset_client_state();
  nvhttp::test_support::reload_client_state();
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(disabled_credentials.x509));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(expired_credentials.x509));
}

TEST_F(ClientAuthorizationTest, DuplicateCertificateIdentityFailsClosed) {
  const auto credentials = test_utils::certificates::generate_ca_credentials();
  const auto uuid = nvhttp::test_support::add_client("first", credentials.x509, true);
  ASSERT_FALSE(uuid.empty());
  EXPECT_FALSE(nvhttp::test_support::duplicate_client("missing"));
  ASSERT_TRUE(nvhttp::test_support::duplicate_client(uuid));

  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(credentials.x509));
}

TEST_F(ClientAuthorizationTest, RePairingReplacesDuplicateCertificateIdentity) {
  const auto paired_credentials = test_utils::certificates::generate_ca_credentials();
  const auto other_credentials = test_utils::certificates::generate_ca_credentials("Sunshine Other Client");
  const auto original_uuid = nvhttp::test_support::add_client("original", paired_credentials.x509, true);
  const auto other_uuid = nvhttp::test_support::add_client("other", other_credentials.x509, true);
  ASSERT_FALSE(original_uuid.empty());
  ASSERT_FALSE(other_uuid.empty());
  ASSERT_TRUE(nvhttp::test_support::duplicate_client(original_uuid));
  ASSERT_EQ(nvhttp::get_all_clients().size(), 3);
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));

  const auto repaired_uuid = nvhttp::test_support::add_client(
    "repaired",
    test_utils::certificates::to_crlf_pem(paired_credentials.x509),
    true
  );

  ASSERT_FALSE(repaired_uuid.empty());
  EXPECT_NE(repaired_uuid, original_uuid);
  EXPECT_EQ(nvhttp::get_all_clients().size(), 2);
  EXPECT_EQ(nvhttp::get_cert_by_uuid(repaired_uuid), paired_credentials.x509);
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(other_credentials.x509));

  nvhttp::test_support::reset_client_state();
  nvhttp::test_support::reload_client_state();
  EXPECT_EQ(nvhttp::get_all_clients().size(), 2);
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(paired_credentials.x509));
  EXPECT_TRUE(nvhttp::test_support::authorize_client_certificate(other_credentials.x509));
}

TEST_F(ClientAuthorizationTest, ConcurrentStateChangesRemainConsistent) {
  const auto credentials = test_utils::certificates::generate_ca_credentials();
  const auto uuid = nvhttp::test_support::add_client("concurrent", credentials.x509, true);
  ASSERT_FALSE(uuid.empty());

  std::atomic_bool operations_succeeded {true};
  std::vector<std::jthread> workers;
  for (std::size_t worker = 0; worker < 4; ++worker) {
    workers.emplace_back([&operations_succeeded, uuid, certificate = credentials.x509, worker]() {
      for (std::size_t iteration = 0; iteration < 8; ++iteration) {
        if (!nvhttp::set_client_enabled(uuid, (worker + iteration) % 2 == 0)) {
          operations_succeeded = false;
        }
        static_cast<void>(nvhttp::test_support::authorize_client_certificate(certificate));
      }
    });
  }
  workers.clear();

  EXPECT_TRUE(operations_succeeded);
  ASSERT_TRUE(nvhttp::set_client_enabled(uuid, false));
  EXPECT_FALSE(nvhttp::test_support::authorize_client_certificate(credentials.x509));
}

TEST_F(ClientAuthorizationTest, RequireAcceptPersistsAndExposesJsonField) {
  const auto credentials = test_utils::certificates::generate_ca_credentials("Sunshine Reconnect Client");
  const auto uuid = nvhttp::test_support::add_client("Stream Client", credentials.x509, true);
  ASSERT_FALSE(uuid.empty());
  EXPECT_FALSE(nvhttp::set_client_require_accept("missing-uuid", true));

  auto clients = nvhttp::get_all_clients();
  ASSERT_EQ(clients.size(), 1);
  EXPECT_FALSE(clients.front().at("require_accept").get<bool>());

  ASSERT_TRUE(nvhttp::set_client_require_accept(uuid, true));
  clients = nvhttp::get_all_clients();
  ASSERT_EQ(clients.size(), 1);
  EXPECT_TRUE(clients.front().at("require_accept").get<bool>());

  nvhttp::test_support::reset_client_state();
  nvhttp::test_support::reload_client_state();

  clients = nvhttp::get_all_clients();
  ASSERT_EQ(clients.size(), 1);
  EXPECT_EQ(clients.front().at("uuid").get<std::string>(), uuid);
  EXPECT_TRUE(clients.front().at("require_accept").get<bool>());

  ASSERT_TRUE(nvhttp::set_client_require_accept(uuid, false));
  EXPECT_FALSE(nvhttp::get_all_clients().front().at("require_accept").get<bool>());
}

TEST_F(ClientAuthorizationTest, ReconnectQueueLifecycleSupersedesExpiresBoundsAndCancelsOnClientRemoval) {
  EXPECT_TRUE(nvhttp::test_support::enqueue_reconnect_for_testing("missing", "192.0.2.1", "launch").empty());

  const auto first_creds = test_utils::certificates::generate_ca_credentials("Client One");
  const auto second_creds = test_utils::certificates::generate_ca_credentials("Client Two");
  const auto first_uuid = nvhttp::test_support::add_client("Desktop", first_creds.x509, true);
  const auto second_uuid = nvhttp::test_support::add_client("Tablet", second_creds.x509, true);
  ASSERT_FALSE(first_uuid.empty());
  ASSERT_FALSE(second_uuid.empty());

  const auto initial_id = nvhttp::test_support::enqueue_reconnect_for_testing(first_uuid, "192.0.2.10", "launch");
  ASSERT_FALSE(initial_id.empty());
  const auto superseded_id = nvhttp::test_support::enqueue_reconnect_for_testing(first_uuid, "192.0.2.11", "resume");
  ASSERT_FALSE(superseded_id.empty());
  EXPECT_NE(initial_id, superseded_id);

  auto pending = nvhttp::get_pending_reconnects();
  ASSERT_EQ(pending.size(), 1);
  EXPECT_EQ(pending.front().id, superseded_id);
  EXPECT_EQ(pending.front().uuid, first_uuid);
  EXPECT_EQ(pending.front().name, "Desktop");
  EXPECT_EQ(pending.front().address, "192.0.2.11");
  EXPECT_EQ(pending.front().action, "resume");

  EXPECT_FALSE(nvhttp::resolve_pending_reconnect("invalid-id", true));
  EXPECT_FALSE(nvhttp::resolve_pending_reconnect(initial_id, true));
  EXPECT_TRUE(nvhttp::resolve_pending_reconnect(superseded_id, false));
  EXPECT_TRUE(nvhttp::get_pending_reconnects().empty());

  bool approved_callback_ran = false;
  const auto approve_id = nvhttp::test_support::enqueue_reconnect_for_testing(
    first_uuid,
    "192.0.2.12",
    "launch",
    [&approved_callback_ran]() {
      approved_callback_ran = true;
    }
  );
  ASSERT_FALSE(approve_id.empty());
  EXPECT_TRUE(nvhttp::resolve_pending_reconnect(approve_id, true));
  EXPECT_TRUE(approved_callback_ran);
  EXPECT_TRUE(nvhttp::get_pending_reconnects().empty());

  const auto disabled_id = nvhttp::test_support::enqueue_reconnect_for_testing(first_uuid, "192.0.2.13", "launch");
  const auto kept_id = nvhttp::test_support::enqueue_reconnect_for_testing(second_uuid, "192.0.2.14", "launch");
  ASSERT_FALSE(disabled_id.empty());
  ASSERT_FALSE(kept_id.empty());
  ASSERT_TRUE(nvhttp::set_client_enabled(first_uuid, false));
  pending = nvhttp::get_pending_reconnects();
  ASSERT_EQ(pending.size(), 1);
  EXPECT_EQ(pending.front().id, kept_id);

  ASSERT_TRUE(nvhttp::unpair_client(second_uuid));
  EXPECT_TRUE(nvhttp::get_pending_reconnects().empty());

  std::vector<std::string> bounded_uuids;
  for (std::size_t index = 0; index < nvhttp::MAX_PENDING_RECONNECT_REQUESTS; ++index) {
    const auto creds = test_utils::certificates::generate_ca_credentials(std::format("Bounded {}", index));
    const auto uuid = nvhttp::test_support::add_client(std::format("Client {}", index), creds.x509, true);
    ASSERT_FALSE(uuid.empty());
    bounded_uuids.push_back(uuid);
    EXPECT_FALSE(nvhttp::test_support::enqueue_reconnect_for_testing(uuid, "192.0.2.20", "launch").empty());
  }
  const auto overflow_creds = test_utils::certificates::generate_ca_credentials("Overflow Client");
  const auto overflow_uuid = nvhttp::test_support::add_client("Overflow", overflow_creds.x509, true);
  ASSERT_FALSE(overflow_uuid.empty());
  EXPECT_TRUE(nvhttp::test_support::enqueue_reconnect_for_testing(overflow_uuid, "192.0.2.99", "launch").empty());
  EXPECT_EQ(nvhttp::get_pending_reconnects().size(), nvhttp::MAX_PENDING_RECONNECT_REQUESTS);

  nvhttp::expire_pending_reconnects(std::chrono::steady_clock::now() + nvhttp::RECONNECT_APPROVAL_TIMEOUT + std::chrono::seconds {1});
  EXPECT_TRUE(nvhttp::get_pending_reconnects().empty());

  EXPECT_FALSE(nvhttp::test_support::enqueue_reconnect_for_testing(bounded_uuids.front(), "192.0.2.21", "launch").empty());
  nvhttp::erase_all_clients();
  EXPECT_TRUE(nvhttp::get_pending_reconnects().empty());
}

TEST_F(ClientAuthorizationTest, HttpsStreamServerHoldsAndResolvesReconnectRequests) {
  using namespace std::chrono_literals;

  const auto server_creds = crypto::gen_creds("Sunshine Reconnect Server", 2048);
  const auto client_creds = test_utils::certificates::generate_ca_credentials("Sunshine Reconnect Client");

  const auto temp_dir = fs::path {SUNSHINE_TEST_BIN_DIR} / "reconnect_https_test";
  fs::create_directories(temp_dir);
  const auto server_cert_file = temp_dir / "server_cert.pem";
  const auto server_key_file = temp_dir / "server_key.pem";
  const auto client_cert_file = temp_dir / "client_cert.pem";
  const auto client_key_file = temp_dir / "client_key.pem";
  {
    std::ofstream {server_cert_file} << server_creds.x509;
    std::ofstream {server_key_file} << server_creds.pkey;
    std::ofstream {client_cert_file} << client_creds.x509;
    std::ofstream {client_key_file} << client_creds.pkey;
  }

  const auto uuid = nvhttp::test_support::add_client("Living Room TV", client_creds.x509, true);
  ASSERT_FALSE(uuid.empty());
  ASSERT_TRUE(nvhttp::set_client_require_accept(uuid, true));

  bool host_audio = false;
  auto server = nvhttp::test_support::make_stream_https_server(server_cert_file.string(), server_key_file.string(), host_audio);
  server->config.address = "127.0.0.1";
  server->config.port = 0;

  unsigned short port = 0;
  std::jthread server_thread([&]() {
    server->start([&port](const unsigned short assigned_port) {
      port = assigned_port;
    });
  });

  for (int attempt = 0; attempt < 200 && port == 0; ++attempt) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_NE(port, 0);

  const std::string launch_path =
    "/launch?appid=0&rikey=00112233445566778899aabbccddeeff&rikeyid=1&localAudioPlayMode=0";

  auto send_async_get = [&](const std::string &path) {
    return std::async(std::launch::async, [&, path]() {
      SimpleWeb::Client<SimpleWeb::HTTPS> https_client(
        std::format("127.0.0.1:{}", port),
        false,
        client_cert_file.string(),
        client_key_file.string()
      );
      https_client.config.timeout = 5;
      const auto response = https_client.request("GET", path);
      return response->content.string();
    });
  };

  auto wait_for_pending_id = [&](const std::string_view previous_id = {}) {
    for (int attempt = 0; attempt < 200; ++attempt) {
      const auto pending = nvhttp::get_pending_reconnects();
      if (!pending.empty() && pending.front().id != previous_id) {
        return pending.front().id;
      }
      std::this_thread::sleep_for(10ms);
    }
    return std::string {};
  };

  // Deny flow holds `/launch` until operator rejects it with 403.
  auto denied_future = send_async_get(launch_path);
  const auto denied_id = wait_for_pending_id();
  ASSERT_FALSE(denied_id.empty());
  EXPECT_EQ(denied_future.wait_for(50ms), std::future_status::timeout);
  ASSERT_TRUE(nvhttp::resolve_pending_reconnect(denied_id, false));
  const auto denied_xml = denied_future.get();
  EXPECT_TRUE(denied_xml.contains("status_code=\"403\""));
  EXPECT_TRUE(denied_xml.contains("<gamesession>0</gamesession>"));

  // Supersede flow rejects the earlier held request with 409 and keeps the newer one pending.
  auto first_future = send_async_get(launch_path);
  const auto first_id = wait_for_pending_id();
  ASSERT_FALSE(first_id.empty());

  auto second_future = send_async_get(launch_path);
  const auto second_id = wait_for_pending_id(first_id);
  ASSERT_FALSE(second_id.empty());
  EXPECT_NE(first_id, second_id);

  const auto superseded_xml = first_future.get();
  EXPECT_TRUE(superseded_xml.contains("status_code=\"409\""));

  // Expiring the second held request returns 408.
  nvhttp::expire_pending_reconnects(std::chrono::steady_clock::now() + nvhttp::RECONNECT_APPROVAL_TIMEOUT + 1s);
  const auto expired_xml = second_future.get();
  EXPECT_TRUE(expired_xml.contains("status_code=\"408\""));

  server->stop();
  if (server_thread.joinable()) {
    server_thread.join();
  }
  std::error_code remove_error;
  fs::remove_all(temp_dir, remove_error);
}
