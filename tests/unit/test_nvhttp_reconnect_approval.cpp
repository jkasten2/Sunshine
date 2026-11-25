/**
 * @file tests/unit/test_nvhttp_reconnect_approval.cpp
 * @brief Test per-client reconnect approval, queue lifecycle, and `/cancel` enforcement.
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
#include <vector>

// lib includes
#include <Simple-Web-Server/client_https.hpp>

// local includes
#include <src/config.h>
#include <src/nvhttp.h>

namespace fs = std::filesystem;

/**
 * @brief Isolate reconnect-approval tests from the user's Sunshine state.
 */
class ReconnectApprovalTest: public BaseTest {
protected:
  /**
   * @brief Redirect persisted client state to the test build directory.
   */
  void SetUp() override {
    BaseTest::SetUp();
    original_state_file = config::nvhttp.file_state;
    original_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
    state_file = fs::path {SUNSHINE_TEST_BIN_DIR} / "reconnect_approval_state.json";

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
  bool original_fresh_state = false;  ///< Fresh-state flag restored after each test.
};

namespace {
  /**
   * @brief RAII loopback HTTPS server configured with a single paired client for stream-endpoint tests.
   */
  struct StreamHttpsTestServer {
    /**
     * @brief Start the HTTPS server and register a paired client with the requested `require_accept` flag.
     *
     * @param subdir Subdirectory under `SUNSHINE_TEST_BIN_DIR` for temporary PEM files.
     * @param require_accept Whether `/launch`, `/resume`, and `/cancel` require operator approval.
     */
    StreamHttpsTestServer(const std::string_view subdir, const bool require_accept):
        temp_dir(fs::path {SUNSHINE_TEST_BIN_DIR} / subdir),
        client_cert_file(temp_dir / "client_cert.pem"),
        client_key_file(temp_dir / "client_key.pem") {
      using namespace std::chrono_literals;

      const auto server_creds = crypto::gen_creds("Sunshine Test Stream Server", 2048);
      const auto client_creds = test_utils::certificates::generate_ca_credentials("Sunshine Test Stream Client");

      fs::create_directories(temp_dir);
      const auto server_cert_file = temp_dir / "server_cert.pem";
      const auto server_key_file = temp_dir / "server_key.pem";
      {
        std::ofstream {server_cert_file} << server_creds.x509;
        std::ofstream {server_key_file} << server_creds.pkey;
        std::ofstream {client_cert_file} << client_creds.x509;
        std::ofstream {client_key_file} << client_creds.pkey;
      }

      uuid = nvhttp::test_support::add_client("Living Room TV", client_creds.x509, true);
      EXPECT_FALSE(uuid.empty());
      EXPECT_TRUE(nvhttp::set_client_require_accept(uuid, require_accept));

      server = nvhttp::test_support::make_stream_https_server(server_cert_file.string(), server_key_file.string(), host_audio);
      server->config.address = "127.0.0.1";
      server->config.port = 0;
      server_thread = std::jthread([this]() {
        server->start([this](const unsigned short assigned_port) {
          port = assigned_port;
        });
      });

      for (int attempt = 0; attempt < 200 && port == 0; ++attempt) {
        std::this_thread::sleep_for(10ms);
      }
      EXPECT_NE(port, 0);
    }

    /**
     * @brief Stop the HTTPS server and clean up temporary credential files.
     */
    ~StreamHttpsTestServer() {
      if (server) {
        server->stop();
      }
      if (server_thread.joinable()) {
        server_thread.join();
      }
      std::error_code remove_error;
      fs::remove_all(temp_dir, remove_error);
    }

    /**
     * @brief Perform a synchronous HTTPS GET request as the paired client.
     *
     * @param path Request path and query string.
     * @return Response body string.
     */
    std::string get(const std::string &path) const {
      SimpleWeb::Client<SimpleWeb::HTTPS> https_client(
        std::format("127.0.0.1:{}", port.load()),
        false,
        client_cert_file.string(),
        client_key_file.string()
      );
      https_client.config.timeout = 5;
      return https_client.request("GET", path)->content.string();
    }

    /**
     * @brief Perform an asynchronous HTTPS GET request as the paired client.
     *
     * @param path Request path and query string.
     * @return Future resolving to the response body string.
     */
    std::future<std::string> async_get(const std::string &path) const {
      return std::async(std::launch::async, [this, path]() {
        return get(path);
      });
    }

    fs::path temp_dir;  ///< Temporary directory holding generated PEM files.
    fs::path client_cert_file;  ///< Paired client certificate path.
    fs::path client_key_file;  ///< Paired client private key path.
    std::string uuid;  ///< Persistent UUID of the paired client.
    bool host_audio = false;  ///< Host-audio state updated by stream handlers.
    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> server;  ///< Loopback HTTPS server.
    std::jthread server_thread;  ///< Background thread running the HTTPS server.
    std::atomic<unsigned short> port {0};  ///< Assigned loopback port.
  };
}  // namespace

TEST_F(ReconnectApprovalTest, RequireAcceptPersistsAndExposesJsonField) {
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

TEST_F(ReconnectApprovalTest, ReconnectQueueLifecycleSupersedesExpiresBoundsAndCancelsOnClientRemoval) {
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
    const auto creds = crypto::gen_creds(std::format("Bounded {}", index), 1024);
    const auto uuid = nvhttp::test_support::add_client(std::format("Client {}", index), creds.x509, true);
    ASSERT_FALSE(uuid.empty());
    bounded_uuids.push_back(uuid);
    EXPECT_FALSE(nvhttp::test_support::enqueue_reconnect_for_testing(uuid, "192.0.2.20", "launch").empty());
  }
  const auto overflow_creds = crypto::gen_creds("Overflow Client", 1024);
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

TEST_F(ReconnectApprovalTest, HttpsStreamServerHoldsAndResolvesReconnectRequests) {
  using namespace std::chrono_literals;

  StreamHttpsTestServer https_server("reconnect_https_test", true);

  const std::string launch_path =
    "/launch?appid=0&rikey=00112233445566778899aabbccddeeff&rikeyid=1&localAudioPlayMode=0";

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
  auto denied_future = https_server.async_get(launch_path);
  const auto denied_id = wait_for_pending_id();
  ASSERT_FALSE(denied_id.empty());
  EXPECT_EQ(denied_future.wait_for(50ms), std::future_status::timeout);
  ASSERT_TRUE(nvhttp::resolve_pending_reconnect(denied_id, false));
  const auto denied_xml = denied_future.get();
  EXPECT_TRUE(denied_xml.contains("status_code=\"403\""));
  EXPECT_TRUE(denied_xml.contains("<gamesession>0</gamesession>"));

  // Supersede flow rejects the earlier held request with 409 and keeps the newer one pending.
  auto first_future = https_server.async_get(launch_path);
  const auto first_id = wait_for_pending_id();
  ASSERT_FALSE(first_id.empty());

  auto second_future = https_server.async_get(launch_path);
  const auto second_id = wait_for_pending_id(first_id);
  ASSERT_FALSE(second_id.empty());
  EXPECT_NE(first_id, second_id);

  const auto superseded_xml = first_future.get();
  EXPECT_TRUE(superseded_xml.contains("status_code=\"409\""));

  // Expiring the second held request returns 408.
  nvhttp::expire_pending_reconnects(std::chrono::steady_clock::now() + nvhttp::RECONNECT_APPROVAL_TIMEOUT + 1s);
  const auto expired_xml = second_future.get();
  EXPECT_TRUE(expired_xml.contains("status_code=\"408\""));
}

TEST_F(ReconnectApprovalTest, HttpsStreamServerRejectsCancelWhenRequireAcceptEnabled) {
  StreamHttpsTestServer https_server("cancel_reject_https_test", true);

  const auto cancel_xml = https_server.get("/cancel");
  EXPECT_TRUE(cancel_xml.contains("status_code=\"403\""));
  EXPECT_TRUE(cancel_xml.contains("<cancel>0</cancel>"));
  EXPECT_TRUE(nvhttp::get_pending_reconnects().empty());
}

TEST_F(ReconnectApprovalTest, HttpsStreamServerAllowsCancelWhenRequireAcceptDisabled) {
  StreamHttpsTestServer https_server("cancel_allow_https_test", false);

  const auto cancel_xml = https_server.get("/cancel");
  EXPECT_TRUE(cancel_xml.contains("status_code=\"200\""));
  EXPECT_TRUE(cancel_xml.contains("<cancel>1</cancel>"));
}
