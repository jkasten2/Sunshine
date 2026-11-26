/**
 * @file src/nvhttp.cpp
 * @brief Definitions for the nvhttp (GameStream) server.
 */
// macros
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <format>
#include <mutex>
#include <string>
#include <utility>

// lib includes
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/context_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <Simple-Web-Server/server_http.hpp>

// local includes
#include "config.h"
#include "display_device.h"
#include "file_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "string_hash.h"
#include "system_tray.h"
#include "utility.h"
#include "uuid.h"
#include "video.h"

using namespace std::literals;

namespace nvhttp {

  static constexpr std::string_view EMPTY_PROPERTY_TREE_ERROR_MSG = "Property tree is empty. Probably, control flow got interrupted by an unexpected C++ exception. This is a bug in Sunshine. Moonlight-qt will report Malformed XML (missing root element)."sv;

  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  crypto::cert_chain_t cert_chain;  ///< Enabled paired-client certificates accepted by Sunshine's GameStream HTTPS server.

  /**
   * @brief Get the mutex protecting paired-client authorization state.
   *
   * @return Mutex serializing paired-client state and certificate authorization changes.
   */
  std::mutex &client_auth_mutex() {
    static std::mutex mutex;
    return mutex;
  }

  /**
   * @brief HTTPS server backend that adds Sunshine's client-certificate verification.
   */
  class SunshineHTTPSServer: public SimpleWeb::ServerBase<SunshineHTTPS> {
  public:
    /**
     * @brief Initialize the HTTPS server with Sunshine's certificate and key files.
     *
     * @param certification_file Path to the server certificate file.
     * @param private_key_file Path to the matching private key file.
     */
    SunshineHTTPSServer(const std::string &certification_file, const std::string &private_key_file):
        ServerBase<SunshineHTTPS>::ServerBase(443) {
      // Disabling TLS 1.0 and 1.1 (see RFC 8996)
      context.set_options(boost::asio::ssl::context::no_tlsv1);
      context.set_options(boost::asio::ssl::context::no_tlsv1_1);
      context.use_certificate_chain_file(certification_file);
      context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
    }

    std::function<int(SSL *)> verify;  ///< Callback that validates a client's TLS certificate after handshake.
    std::function<void(const std::shared_ptr<Request> &, SSL *)> on_verified;  ///< Optional callback invoked after TLS client verification succeeds.
    std::function<void(std::shared_ptr<Response>, std::shared_ptr<Request>)> on_verify_failed;  ///< Handler used to return the pairing challenge when client verification fails.

    /**
     * @brief Post a callback onto the server's I/O context guarded by its handler lifetime scope.
     *
     * @param callback Work item to execute on the HTTPS server thread while the server remains active.
     */
    void post_guarded(std::function<void()> callback) {
      if (!io_service || !handler_runner) {
        callback();
        return;
      }
      boost::asio::post(*io_service, [runner = handler_runner, cb = std::move(callback)]() mutable {
        if (auto lock = runner->continue_lock(); lock) {
          cb();
        }
      });
    }

  protected:
    boost::asio::ssl::context context {boost::asio::ssl::context::tls_server};  ///< TLS server context configured with Sunshine's certificate and protocol policy.

    /**
     * @brief Enable client-certificate verification after the listening socket is bound.
     * @details Ignore the TLS preverification result and context so failed authorization can receive an HTTP error.
     */
    void after_bind() override {
      if (verify) {
        context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
        context.set_verify_callback([](int, boost::asio::ssl::verify_context &) {
          // To respond with an error message, a connection must be established
          return 1;
        });
      }
    }

    /**
     * @brief Process a completed TLS handshake under the callback's server lifetime guard.
     *
     * @param session Session whose TLS handshake has completed.
     * @param ec Result of the asynchronous handshake.
     * @pre The caller holds the session's handler scope guard.
     */
    void handle_handshake(const std::shared_ptr<Session> &session, const SimpleWeb::error_code &ec) {
      if (!ec) {
        auto *ssl = session->connection->socket->native_handle();
        if (verify && !verify(ssl)) {
          this->write(session, on_verify_failed);
        } else {
          if (on_verified) {
            on_verified(session->request, ssl);
          }
          this->read(session);
        }
      } else if (this->on_error) {
        this->on_error(session->request, ec);
      }
    }

    // This is Server<HTTPS>::accept() with SSL validation support added
    /**
     * @brief Accept a pending connection and arm the server for the next client.
     * @details Keep each handler's scope guard alive until all access to the server has finished.
     */
    void accept() override {
      auto connection = create_connection(*io_service, context);

      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const SimpleWeb::error_code &ec) {
        if (auto lock = connection->handler_runner->continue_lock(); lock) {
          if (ec != SimpleWeb::error::operation_aborted) {
            this->accept();
          }

          auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

          if (!ec) {
            boost::asio::ip::tcp::no_delay option(true);
            SimpleWeb::error_code option_error;
            session->connection->socket->lowest_layer().set_option(option, option_error);

            session->connection->set_timeout(config.timeout_request);
            session->connection->socket->async_handshake(boost::asio::ssl::stream_base::server, [this, session](const SimpleWeb::error_code &ec) {
              session->connection->cancel_timeout();
              if (auto lock = session->connection->handler_runner->continue_lock(); lock) {
                this->handle_handshake(session, ec);
              }
            });
          } else if (this->on_error) {
            this->on_error(session->request, ec);
          }
        }
      });
    }
  };

  /**
   * @brief HTTPS server type used for GameStream endpoints requiring TLS.
   */
  using https_server_t = SunshineHTTPSServer;
  /**
   * @brief Plain HTTP server type used for GameStream endpoints without TLS.
   */
  using http_server_t = SimpleWeb::Server<SimpleWeb::HTTP>;

  /**
   * @brief Internal HTTPS credential paths for the configuration server.
   */
  struct conf_intern_t {
    std::string servercert;  ///< Server certificate PEM string.
    std::string pkey;  ///< Private key PEM string or path.
  };

  conf_intern_t conf_intern;  ///< TLS credential paths loaded from Sunshine's runtime configuration.

  /**
   * @brief Certificate entry associated with a client name and UUID.
   */
  struct named_cert_t {
    std::string name;  ///< Human-readable name for this item.
    std::string uuid;  ///< Persistent Moonlight client UUID associated with the certificate.
    std::string cert;  ///< Certificate PEM string or path.
    bool enabled = true;  ///< Whether this persisted client entry may connect.
    bool require_accept = false;  ///< Whether starting or resuming a stream requires operator approval.
  };

  /**
   * @brief Persisted pairing data for one Moonlight client.
   */
  struct client_t {
    std::vector<named_cert_t> named_devices;  ///< Persisted Moonlight clients allowed to pair or reconnect.
  };

  // uniqueID, session
  std::unordered_map<std::string, pair_session_t, util::transparent_string_hash, std::equal_to<>> map_id_sess;  ///< Pairing sessions keyed by temporary unique ID.

  /**
   * @brief Get the mutex protecting pairing-session state.
   *
   * @return Mutex serializing pairing-session storage and lifecycle transitions.
   */
  std::mutex &map_id_sess_mutex() {
    static std::mutex mutex;
    return mutex;
  }

  client_t client_root;  ///< In-memory representation of the paired-client database.
  std::atomic<uint32_t> session_id_counter;  ///< Monotonic counter used to allocate GameStream session IDs.

  // Set by TLS verify callback, read by launch/resume handler (single-threaded HTTPS server)
  std::string last_verified_client_cert;  ///< Last client certificate accepted by the TLS verify callback.  // NOSONAR(cpp:S5421): intentionally mutable global
  std::string last_verified_client_name;  ///< Friendly name of last client certificate accepted by the TLS verify callback. // NOSONAR(cpp:S5421): intentionally mutable global

  /**
   * @brief Case-insensitive map used for HTTP headers and query parameters.
   */
  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  /**
   * @brief Shared HTTPS response object passed to GameStream handlers.
   */
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Response>;
  /**
   * @brief Shared HTTPS request object received by GameStream handlers.
   */
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Request>;
  /**
   * @brief Shared HTTP response object passed to redirect and discovery handlers.
   */
  using resp_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>;
  /**
   * @brief Shared HTTP request object received by redirect and discovery handlers.
   */
  using req_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Request>;

  /**
   * @brief Certificate operations supported by the pairing API.
   */
  enum class op_e {
    ADD,  ///< Add certificate
    REMOVE  ///< Remove certificate
  };

  /**
   * @brief Read a named query argument from the HTTP request map.
   *
   * @param args Parsed query-string argument map.
   * @param name Query parameter name to read.
   * @param default_value Value returned when the parameter is absent.
   * @return Query parameter value, default value, or an empty string.
   */
  std::string get_arg(const args_t &args, const char *name, const char *default_value = nullptr) {
    auto it = args.find(name);
    if (it == std::end(args)) {
      if (default_value != nullptr) {
        return std::string(default_value);
      }

      throw std::out_of_range(name);
    }
    return it->second;
  }

  /**
   * @brief Persist the current state to its backing store.
   */
  void save_state() {
    pt::ptree root;

    if (fs::exists(config::nvhttp.file_state)) {
      try {
        pt::read_json(config::nvhttp.file_state, root);
      } catch (std::exception &e) {
        BOOST_LOG(error) << "Couldn't read "sv << config::nvhttp.file_state << ": "sv << e.what();
        return;
      }
    }

    root.erase("root"s);

    root.put("root.uniqueid", http::unique_id);
    client_t &client = client_root;
    pt::ptree node;

    pt::ptree named_cert_nodes;
    for (auto &named_cert : client.named_devices) {
      pt::ptree named_cert_node;
      named_cert_node.put("name"s, named_cert.name);
      named_cert_node.put("cert"s, named_cert.cert);
      named_cert_node.put("uuid"s, named_cert.uuid);
      named_cert_node.put("enabled"s, named_cert.enabled);
      named_cert_node.put("require_accept"s, named_cert.require_accept);
      named_cert_nodes.push_back(std::make_pair(""s, named_cert_node));
    }
    root.add_child("root.named_devices"s, named_cert_nodes);

    try {
      pt::write_json(config::nvhttp.file_state, root);
    } catch (std::exception &e) {
      BOOST_LOG(error) << "Couldn't write "sv << config::nvhttp.file_state << ": "sv << e.what();
      return;
    }
  }

  /**
   * @brief Convert a PEM certificate to Sunshine's canonical OpenSSL serialization.
   *
   * @param cert_pem PEM-encoded certificate to canonicalize.
   * @return Canonical PEM text, or an empty string when the certificate is invalid.
   */
  std::string canonical_certificate_pem(const std::string_view cert_pem) {
    auto certificate = crypto::x509(cert_pem);
    return certificate ? crypto::pem(certificate) : std::string {};
  }

  /**
   * @brief Rebuild the GameStream trust stores from enabled paired-client records.
   *
   * @note The caller must hold `client_auth_mutex()`.
   */
  void rebuild_client_cert_chain() {
    cert_chain.clear();
    for (const auto &named_cert : client_root.named_devices) {
      if (!named_cert.enabled) {
        continue;
      }

      auto certificate = crypto::x509(named_cert.cert);
      if (!certificate) {
        BOOST_LOG(warning) << "Ignoring invalid paired-client certificate"sv;
        continue;
      }

      cert_chain.add(std::move(certificate));
    }
  }

  /**
   * @brief Check whether a certificate exactly matches an enabled paired-client record.
   *
   * @param certificate Parsed client certificate to compare by canonical X.509 identity.
   * @return `true` only when exactly one matching paired-client record is enabled.
   * @note The caller must hold `client_auth_mutex()`.
   */
  bool is_client_enabled(const X509 *certificate) {
    bool matched = false;
    for (const auto &named_cert : client_root.named_devices) {
      if (auto stored_certificate = crypto::x509(named_cert.cert); !stored_certificate || X509_cmp(stored_certificate.get(), certificate) != 0) {
        continue;
      }

      if (matched || !named_cert.enabled) {
        return false;
      }
      matched = true;
    }
    return matched;
  }

  /**
   * @brief Verify a client certificate against the exact enabled paired identity.
   *
   * @param certificate Parsed client certificate presented during the TLS handshake.
   * @return `nullptr` when authorized, otherwise a non-sensitive error string.
   * @note The caller must hold `client_auth_mutex()`.
   */
  const char *verify_client_certificate(X509 *certificate) {
    if (const auto verification_error = cert_chain.verify(certificate); verification_error) {
      return verification_error;
    }
    return is_client_enabled(certificate) ? nullptr : "Client certificate identity is not enabled";
  }

  /**
   * @brief Load state from its backing store.
   */
  void load_state() {
    if (!fs::exists(config::nvhttp.file_state)) {
      BOOST_LOG(info) << "File "sv << config::nvhttp.file_state << " doesn't exist"sv;
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }

    pt::ptree tree;
    try {
      pt::read_json(config::nvhttp.file_state, tree);
    } catch (std::exception &e) {
      BOOST_LOG(error) << "Couldn't read "sv << config::nvhttp.file_state << ": "sv << e.what();

      return;
    }

    auto unique_id_p = tree.get_optional<std::string>("root.uniqueid");
    if (!unique_id_p) {
      // This file doesn't contain moonlight credentials
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }
    http::unique_id = std::move(*unique_id_p);

    auto root = tree.get_child("root");
    client_t client;

    // Import from old format
    if (root.get_child_optional("devices")) {
      auto device_nodes = root.get_child("devices");
      for (auto &[_, device_node] : device_nodes) {
        auto uniqID = device_node.get<std::string>("uniqueid");

        if (device_node.count("certs")) {
          for (auto &[_, el] : device_node.get_child("certs")) {
            named_cert_t named_cert;
            named_cert.name = ""s;
            named_cert.cert = el.get_value<std::string>();
            named_cert.uuid = uuid_util::uuid_t::generate().string();
            client.named_devices.emplace_back(named_cert);
          }
        }
      }
    }

    if (root.count("named_devices")) {
      for (auto &[_, el] : root.get_child("named_devices")) {
        named_cert_t named_cert;
        named_cert.name = el.get_child("name").get_value<std::string>();
        named_cert.cert = el.get_child("cert").get_value<std::string>();
        named_cert.uuid = el.get_child("uuid").get_value<std::string>();
        named_cert.enabled = el.get<bool>("enabled", true);
        named_cert.require_accept = el.get<bool>("require_accept", false);
        client.named_devices.emplace_back(named_cert);
      }
    }

    for (auto &named_cert : client.named_devices) {
      auto canonical_certificate = canonical_certificate_pem(named_cert.cert);
      if (!canonical_certificate.empty()) {
        named_cert.cert = std::move(canonical_certificate);
      }
    }

    std::lock_guard lock {client_auth_mutex()};
    client_root = std::move(client);
    rebuild_client_cert_chain();
  }

  /**
   * @brief Add authorized client data.
   *
   * A completed pairing replaces all records with the same exact X.509 identity so legacy duplicate records cannot make the newly paired client fail authorization.
   *
   * @param name Human-readable name to assign.
   * @param cert Certificate data or object used by the operation.
   * @return Persistent UUID for the added client, or an empty string when the certificate is invalid.
   */
  std::string add_authorized_client(const std::string &name, std::string &&cert) {
    auto certificate = crypto::x509(cert);
    if (!certificate) {
      return {};
    }

    named_cert_t named_cert;
    named_cert.name = name;
    named_cert.cert = crypto::pem(certificate);
    named_cert.uuid = uuid_util::uuid_t::generate().string();
    const auto uuid = named_cert.uuid;

    std::lock_guard lock {client_auth_mutex()};
    std::erase_if(client_root.named_devices, [&certificate](const named_cert_t &existing_client) {
      auto existing_certificate = crypto::x509(existing_client.cert);
      return existing_certificate && X509_cmp(existing_certificate.get(), certificate.get()) == 0;
    });
    client_root.named_devices.emplace_back(std::move(named_cert));
    rebuild_client_cert_chain();

    if (!config::sunshine.flags[config::flag::FRESH_STATE]) {
      save_state();
    }
    return uuid;
  }

  /**
   * @brief Create launch session.
   *
   * @param host_audio Host audio.
   * @param args Arguments forwarded to the callable or parser.
   * @param client_cert Optional verified client certificate PEM override.
   * @param client_name Optional verified client friendly name override.
   * @return Constructed launch session object.
   */
  std::shared_ptr<rtsp_stream::launch_session_t> make_launch_session(
    bool host_audio,
    const args_t &args,
    const std::optional<std::string> &client_cert = std::nullopt,
    const std::optional<std::string> &client_name = std::nullopt
  ) {
    auto launch_session = std::make_shared<rtsp_stream::launch_session_t>();

    launch_session->id = ++session_id_counter;

    auto rikey = util::from_hex_vec(get_arg(args, "rikey"), true);
    std::copy(rikey.cbegin(), rikey.cend(), std::back_inserter(launch_session->gcm_key));

    launch_session->host_audio = host_audio;
    auto mode = std::stringstream(get_arg(args, "mode", "0x0x0"));
    // Split mode by the char "x", to populate width/height/fps
    int x = 0;
    std::string segment;
    while (std::getline(mode, segment, 'x')) {
      if (x == 0) {
        launch_session->width = atoi(segment.c_str());
      }
      if (x == 1) {
        launch_session->height = atoi(segment.c_str());
      }
      if (x == 2) {
        launch_session->fps = atoi(segment.c_str());
      }
      x++;
    }
    // Cap the session resolution up front so downstream consumers (e.g. the display device
    // configuration that switches the host display mode) target the actual streamed size
    // instead of the uncapped client request.
    config::cap_stream_resolution(launch_session->width, launch_session->height);
    launch_session->unique_id = (get_arg(args, "uniqueid", "unknown"));
    launch_session->appid = (int) util::from_view(get_arg(args, "appid", "unknown"));
    launch_session->enable_sops = util::from_view(get_arg(args, "sops", "0"));
    launch_session->surround_info = (int) util::from_view(get_arg(args, "surroundAudioInfo", "196610"));
    launch_session->surround_params = (get_arg(args, "surroundParams", ""));
    launch_session->continuous_audio = util::from_view(get_arg(args, "continuousAudio", "0"));
    launch_session->gcmap = (int) util::from_view(get_arg(args, "gcmap", "0"));
    launch_session->enable_hdr = util::from_view(get_arg(args, "hdrMode", "0"));

    // Encrypted RTSP is enabled with client reported corever >= 1
    auto corever = util::from_view(get_arg(args, "corever", "0"));
    if (corever >= 1) {
      launch_session->rtsp_cipher = crypto::cipher::gcm_t {
        launch_session->gcm_key,
        false
      };
      launch_session->rtsp_iv_counter = 0;
    }
    launch_session->rtsp_url_scheme = launch_session->rtsp_cipher ? "rtspenc://"s : "rtsp://"s;
    launch_session->client_cert = client_cert.value_or(last_verified_client_cert);
    launch_session->client_name = client_name.value_or(last_verified_client_name);

    // Generate the unique identifiers for this connection that we will send later during RTSP handshake
    std::array<unsigned char, 8> raw_payload;
    RAND_bytes(raw_payload.data(), raw_payload.size());
    launch_session->av_ping_payload = util::hex_vec(raw_payload);
    RAND_bytes((unsigned char *) &launch_session->control_connect_data, sizeof(launch_session->control_connect_data));

    launch_session->iv.resize(16);
    uint32_t prepend_iv = util::endian::big<uint32_t>((int) util::from_view(get_arg(args, "rikeyid")));
    auto prepend_iv_p = (uint8_t *) &prepend_iv;
    std::copy(prepend_iv_p, prepend_iv_p + sizeof(prepend_iv), std::begin(launch_session->iv));
    return launch_session;
  }

  /**
   * @brief Write a completed response to the client waiting for PIN approval.
   *
   * @param sess Pairing session that owns the waiting response.
   * @param tree XML response body to write.
   * @return `true` when a live response was available.
   */
  bool write_pairing_response(pair_session_t &sess, const pt::ptree &tree) {
    std::ostringstream data;
    pt::write_xml(data, tree);

    auto &response = sess.async_insert_pin.response;
    if (response.has_left() && response.left()) {
      response.left()->close_connection_after_response = true;
      response.left()->write(data.str());
    } else if (response.has_right() && response.right()) {
      response.right()->close_connection_after_response = true;
      response.right()->write(data.str());
    } else {
      return false;
    }

    response = std::monostate {};
    return true;
  }

  /**
   * @brief Publish the final result of a pairing handshake.
   *
   * @param sess Pairing session whose waiter should be notified.
   * @param success Whether the client completed the authenticated handshake.
   */
  void complete_pairing(pair_session_t &sess, const bool success) {
    {
      std::lock_guard lock {sess.completion->mutex};
      if (sess.completion->result.has_value()) {
        return;
      }
      sess.completion->result = success;
    }
    sess.completion->condition.notify_all();
  }

  /**
   * @brief Expire stale pairing sessions while the session mutex is held.
   *
   * @param now Monotonic time used to evaluate session deadlines.
   */
  void expire_pair_sessions_unlocked(const std::chrono::steady_clock::time_point now) {
    for (auto it = map_id_sess.begin(); it != map_id_sess.end();) {
      if (it->second.async_insert_pin.expires_at > now) {
        ++it;
        continue;
      }

      pt::ptree tree;
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 408);
      tree.put("root.<xmlattr>.status_message", "Pairing session expired");
      write_pairing_response(it->second, tree);
      complete_pairing(it->second, false);
      it = map_id_sess.erase(it);
    }
  }

  pair_session_insert_e insert_pair_session(pair_session_t sess, std::string &pairing_id) {
    std::scoped_lock lock {map_id_sess_mutex()};
    const auto now = std::chrono::steady_clock::now();
    expire_pair_sessions_unlocked(now);
    pairing_id.clear();

    if (map_id_sess.contains(sess.client.uniqueID)) {
      return pair_session_insert_e::ALREADY_EXISTS;
    }
    if (map_id_sess.size() >= MAX_PENDING_PAIRING_SESSIONS) {
      return pair_session_insert_e::FULL;
    }

    do {
      pairing_id = crypto::rand_alphabet(PAIRING_ID_SIZE, "0123456789abcdef"sv);
    } while (std::ranges::any_of(map_id_sess, [&](const auto &entry) {
      return entry.second.async_insert_pin.id == pairing_id;
    }));

    sess.async_insert_pin.id = pairing_id;
    sess.async_insert_pin.expires_at = now + PAIRING_SESSION_TIMEOUT;
    map_id_sess.try_emplace(sess.client.uniqueID, std::move(sess));
    return pair_session_insert_e::ADDED;
  }

  bool evict_abandoned_pair_session(const std::string &unique_id) {
    std::scoped_lock lock {map_id_sess_mutex()};
    const auto sess_it = map_id_sess.find(unique_id);
    if (sess_it == map_id_sess.end() || sess_it->second.last_phase == PAIR_PHASE::NONE) {
      return false;
    }

    complete_pairing(sess_it->second, false);
    map_id_sess.erase(sess_it);
    return true;
  }

  bool is_valid_pairing_id(const std::string_view pairing_id) {
    return pairing_id.size() == PAIRING_ID_SIZE && std::ranges::all_of(pairing_id, [](const char character) {
             return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F');
           });
  }

  bool is_valid_pairing_pin(const std::string_view pin) {
    return pin.size() == 4 && std::ranges::all_of(pin, [](const char character) {
             return character >= '0' && character <= '9';
           });
  }

  bool is_valid_pairing_name(const std::string_view name) {
    return !name.empty() && name.size() <= MAX_PAIRING_CLIENT_NAME_SIZE;
  }

  void expire_pair_sessions(const std::chrono::steady_clock::time_point now) {
    std::scoped_lock lock {map_id_sess_mutex()};
    expire_pair_sessions_unlocked(now);
  }

  std::vector<pending_pairing_t> get_pending_pairings() {
    std::scoped_lock lock {map_id_sess_mutex()};
    expire_pair_sessions_unlocked(std::chrono::steady_clock::now());

    std::vector<const pair_session_t *> pending_sessions;
    pending_sessions.reserve(map_id_sess.size());
    for (const auto &[_, sess] : map_id_sess) {
      if (sess.last_phase == PAIR_PHASE::NONE) {
        pending_sessions.push_back(&sess);
      }
    }
    std::ranges::sort(pending_sessions, {}, [](const pair_session_t *sess) {
      return sess->async_insert_pin.expires_at;
    });

    std::vector<pending_pairing_t> result;
    result.reserve(pending_sessions.size());
    for (const auto *sess : pending_sessions) {
      result.push_back({
        .id = sess->async_insert_pin.id,
        .name = sess->async_insert_pin.device_name,
        .address = sess->async_insert_pin.address,
      });
    }
    return result;
  }

  bool cancel_pairing(const std::string_view pairing_id) {
    if (!is_valid_pairing_id(pairing_id)) {
      return false;
    }

    std::scoped_lock lock {map_id_sess_mutex()};
    expire_pair_sessions_unlocked(std::chrono::steady_clock::now());

    const auto sess_it = std::ranges::find_if(map_id_sess, [&](const auto &entry) {
      return entry.second.last_phase == PAIR_PHASE::NONE && entry.second.async_insert_pin.id == pairing_id;
    });
    if (sess_it == map_id_sess.end()) {
      return false;
    }

    pt::ptree tree;
    tree.put("root.paired", 0);
    tree.put("root.<xmlattr>.status_code", 400);
    tree.put("root.<xmlattr>.status_message", "Pairing request cancelled by operator");
    write_pairing_response(sess_it->second, tree);
    complete_pairing(sess_it->second, false);
    map_id_sess.erase(sess_it);
    return true;
  }

  void remove_session(const pair_session_t &sess) {
    std::scoped_lock lock {map_id_sess_mutex()};
    if (const auto sess_it = map_id_sess.find(sess.client.uniqueID); sess_it != map_id_sess.end()) {
      complete_pairing(sess_it->second, false);
      map_id_sess.erase(sess_it);
    }
  }

  /**
   * @brief Return the GameStream pairing failure response.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param status_msg Status msg.
   */
  void fail_pair(pair_session_t &sess, pt::ptree &tree, const std::string &status_msg) {
    tree.put("root.paired", 0);
    tree.put("root.<xmlattr>.status_code", 400);
    tree.put("root.<xmlattr>.status_message", status_msg);
    sess.failed = true;
    complete_pairing(sess, false);
  }

  /**
   * @brief Return the server certificate text for pairing responses.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param pin PIN supplied by the client during pairing.
   */
  void getservercert(pair_session_t &sess, pt::ptree &tree, const std::string &pin) {
    if (sess.last_phase != PAIR_PHASE::NONE) {
      fail_pair(sess, tree, "Out of order call to getservercert");
      return;
    }
    sess.last_phase = PAIR_PHASE::GETSERVERCERT;

    if (sess.async_insert_pin.salt.size() < 32) {
      fail_pair(sess, tree, "Salt too short");
      return;
    }

    std::string_view salt_view {sess.async_insert_pin.salt.data(), 32};

    auto salt = util::from_hex<std::array<uint8_t, 16>>(salt_view, true);

    auto key = crypto::gen_aes_key(salt, pin);
    sess.cipher_key = std::make_unique<crypto::aes_t>(key);

    tree.put("root.paired", 1);
    tree.put("root.plaincert", util::hex_vec(conf_intern.servercert, true));
    tree.put("root.<xmlattr>.status_code", 200);
  }

  /**
   * @brief Handle the client-challenge phase of GameStream pairing.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param challenge Client challenge bytes from the pairing request.
   */
  void clientchallenge(pair_session_t &sess, pt::ptree &tree, const std::string &challenge) {
    if (sess.last_phase != PAIR_PHASE::GETSERVERCERT) {
      fail_pair(sess, tree, "Out of order call to clientchallenge");
      return;
    }
    sess.last_phase = PAIR_PHASE::CLIENTCHALLENGE;

    if (!sess.cipher_key) {
      fail_pair(sess, tree, "Cipher key not set");
      return;
    }
    crypto::cipher::ecb_t cipher(*sess.cipher_key, false);

    std::vector<uint8_t> decrypted;
    cipher.decrypt(challenge, decrypted);

    auto x509 = crypto::x509(conf_intern.servercert);
    auto sign = crypto::signature(x509);
    auto serversecret = crypto::rand(16);

    decrypted.insert(std::end(decrypted), std::begin(sign), std::end(sign));
    decrypted.insert(std::end(decrypted), std::begin(serversecret), std::end(serversecret));

    auto hash = crypto::hash({(char *) decrypted.data(), decrypted.size()});
    auto serverchallenge = crypto::rand(16);

    std::string plaintext;
    plaintext.reserve(hash.size() + serverchallenge.size());

    plaintext.insert(std::end(plaintext), std::begin(hash), std::end(hash));
    plaintext.insert(std::end(plaintext), std::begin(serverchallenge), std::end(serverchallenge));

    std::vector<uint8_t> encrypted;
    cipher.encrypt(plaintext, encrypted);

    sess.serversecret = std::move(serversecret);
    sess.serverchallenge = std::move(serverchallenge);

    tree.put("root.paired", 1);
    tree.put("root.challengeresponse", util::hex_vec(encrypted, true));
    tree.put("root.<xmlattr>.status_code", 200);
  }

  /**
   * @brief Handle the server-challenge response phase of GameStream pairing.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param encrypted_response Encrypted response.
   */
  void serverchallengeresp(pair_session_t &sess, pt::ptree &tree, const std::string &encrypted_response) {
    if (sess.last_phase != PAIR_PHASE::CLIENTCHALLENGE) {
      fail_pair(sess, tree, "Out of order call to serverchallengeresp");
      return;
    }
    sess.last_phase = PAIR_PHASE::SERVERCHALLENGERESP;

    if (!sess.cipher_key || sess.serversecret.empty()) {
      fail_pair(sess, tree, "Cipher key or serversecret not set");
      return;
    }

    std::vector<uint8_t> decrypted;
    crypto::cipher::ecb_t cipher(*sess.cipher_key, false);

    cipher.decrypt(encrypted_response, decrypted);

    sess.clienthash = std::move(decrypted);

    auto serversecret = sess.serversecret;
    auto sign = crypto::sign256(crypto::pkey(conf_intern.pkey), serversecret);

    serversecret.insert(std::end(serversecret), std::begin(sign), std::end(sign));

    tree.put("root.pairingsecret", util::hex_vec(serversecret, true));
    tree.put("root.paired", 1);
    tree.put("root.<xmlattr>.status_code", 200);
  }

  /**
   * @brief Handle the client pairing-secret phase of GameStream pairing.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param client_pairing_secret Client pairing secret.
   */
  void clientpairingsecret(pair_session_t &sess, pt::ptree &tree, const std::string &client_pairing_secret) {
    if (sess.last_phase != PAIR_PHASE::SERVERCHALLENGERESP) {
      fail_pair(sess, tree, "Out of order call to clientpairingsecret");
      return;
    }
    sess.last_phase = PAIR_PHASE::CLIENTPAIRINGSECRET;

    auto &client = sess.client;

    if (client_pairing_secret.size() <= 16) {
      fail_pair(sess, tree, "Client pairing secret too short");
      return;
    }

    std::string_view secret {client_pairing_secret.data(), 16};
    std::string_view sign {client_pairing_secret.data() + secret.size(), client_pairing_secret.size() - secret.size()};

    auto x509 = crypto::x509(client.cert);
    if (!x509) {
      fail_pair(sess, tree, "Invalid client certificate");
      return;
    }
    auto x509_sign = crypto::signature(x509);

    std::string data;
    data.reserve(sess.serverchallenge.size() + x509_sign.size() + secret.size());

    data.insert(std::end(data), std::begin(sess.serverchallenge), std::end(sess.serverchallenge));
    data.insert(std::end(data), std::begin(x509_sign), std::end(x509_sign));
    data.insert(std::end(data), std::begin(secret), std::end(secret));

    auto hash = crypto::hash(data);

    // if hash not correct, probably MITM
    bool same_hash = hash.size() == sess.clienthash.size() && std::equal(hash.begin(), hash.end(), sess.clienthash.begin());
    auto verify = crypto::verify256(crypto::x509(client.cert), secret, sign);
    bool paired = false;
    if (same_hash && verify) {
      // The client is now successfully paired and will be authorized to connect
      paired = !add_authorized_client(client.name, std::move(client.cert)).empty();
    }

    tree.put("root.paired", paired ? 1 : 0);
    tree.put("root.<xmlattr>.status_code", 200);
    complete_pairing(sess, paired);
  }

  template<class T>
  struct tunnel;

  /**
   * @brief HTTPS tunnel session used for encrypted client requests.
   */
  template<>
  struct tunnel<SunshineHTTPS> {
    static auto constexpr to_string = "HTTPS"sv;  ///< To string.
  };

  /**
   * @brief Plain HTTP server wrapper used for non-TLS endpoints.
   */
  template<>
  struct tunnel<SimpleWeb::HTTP> {
    static auto constexpr to_string = "NONE"sv;  ///< To string.
  };

  /**
   * @brief Write req details to the log.
   *
   * @param request HTTP request data from the client.
   */
  template<class T>
  void print_req(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    BOOST_LOG(debug) << "TUNNEL :: "sv << tunnel<T>::to_string;

    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  /**
   * @brief Return a GameStream HTTP not-found response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void not_found(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response
      << "HTTP/1.1 404 NOT FOUND\r\n"
      << data.str();

    response->close_connection_after_response = true;
  }

  /**
   * @brief Start a GameStream pairing session for a `getservercert` request.
   *
   * @tparam T HTTP server transport type.
   * @param response HTTP response retained while Web UI PIN approval is pending.
   * @param request HTTP request containing the client pairing parameters.
   * @param args Parsed request query parameters.
   * @param tree XML property tree used for immediate responses.
   * @param unique_id Client-provided pairing-session identifier.
   * @return `true` when the response remains pending for Web UI PIN approval.
   */
  template<class T>
  bool start_pairing_session(
    const std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> &response,
    const std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> &request,
    const args_t &args,
    pt::ptree &tree,
    const std::string &unique_id
  ) {
    const bool pin_stdin = config::sunshine.flags[config::flag::PIN_STDIN];
    auto make_session = [&]() {
      pair_session_t fresh_sess;
      fresh_sess.client.uniqueID = unique_id;
      fresh_sess.client.cert = util::from_hex_vec(get_arg(args, "clientcert"), true);
      fresh_sess.async_insert_pin.salt = get_arg(args, "salt");
      fresh_sess.async_insert_pin.device_name = get_arg(args, "devicename");
      fresh_sess.async_insert_pin.address = net::addr_to_normalized_string(request->remote_endpoint().address());
      if (!pin_stdin) {
        fresh_sess.async_insert_pin.response = response;
      }

      BOOST_LOG(debug) << fresh_sess.client.cert;
      return fresh_sess;
    };

    std::string pairing_id;
    auto insert_result = insert_pair_session(make_session(), pairing_id);
    if (insert_result == pair_session_insert_e::ALREADY_EXISTS && evict_abandoned_pair_session(unique_id)) {
      // The previous handshake was abandoned mid-flight; the old session cannot resume,
      // so replace it with a fresh one and retry the insert once.
      insert_result = insert_pair_session(make_session(), pairing_id);
    }
    switch (insert_result) {
      using enum pair_session_insert_e;

      case ALREADY_EXISTS:
        tree.put("root.paired", 0);
        tree.put("root.<xmlattr>.status_code", 409);
        tree.put("root.<xmlattr>.status_message", "A pairing session with this uniqueid already exists");
        return false;
      case FULL:
        tree.put("root.paired", 0);
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Too many pending pairing sessions");
        return false;
      case ADDED:
        break;
      default:
        // All enumerators are handled above; any other value cannot occur.
        std::unreachable();
    }

    if (!pin_stdin) {
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
      system_tray::update_tray_require_pin();
#endif
      return true;
    }

    std::string pin;
    std::cout << "Please insert pin: "sv;
    std::getline(std::cin, pin);

    std::scoped_lock lock {map_id_sess_mutex()};
    expire_pair_sessions_unlocked(std::chrono::steady_clock::now());
    const auto sess_it = map_id_sess.find(unique_id);
    if (sess_it == map_id_sess.end() || sess_it->second.async_insert_pin.id != pairing_id) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 408);
      tree.put("root.<xmlattr>.status_message", "Pairing session expired");
      return false;
    }

    getservercert(sess_it->second, tree, pin);
    if (sess_it->second.failed) {
      map_id_sess.erase(sess_it);
    }
    return false;
  }

  /**
   * @brief Dispatch the top-level GameStream pairing request by phase.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void pair(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    pt::ptree tree;

    auto fg = util::fail_guard([&tree, &response]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto args = request->parse_query_string();
    if (args.find("uniqueid"s) == std::end(args)) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing uniqueid parameter");

      return;
    }

    auto uniqID {get_arg(args, "uniqueid")};

    const auto phrase_it = args.find("phrase");
    if (phrase_it != std::end(args) && phrase_it->second == "getservercert"sv) {
      if (start_pairing_session<T>(response, request, args, tree, uniqID)) {
        fg.disable();
      }
      return;
    }
    if (phrase_it != std::end(args) && phrase_it->second == "pairchallenge"sv) {
      tree.put("root.paired", 1);
      tree.put("root.<xmlattr>.status_code", 200);
      return;
    }

    std::scoped_lock lock {map_id_sess_mutex()};
    expire_pair_sessions_unlocked(std::chrono::steady_clock::now());
    auto sess_it = map_id_sess.find(uniqID);
    if (sess_it == std::end(map_id_sess)) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Invalid uniqueid");

      return;
    }

    bool pairing_complete = false;
    if (const auto challenge_it = args.find("clientchallenge"); challenge_it != std::end(args)) {
      auto challenge = util::from_hex_vec(challenge_it->second, true);
      clientchallenge(sess_it->second, tree, challenge);
    } else if (const auto response_it = args.find("serverchallengeresp"); response_it != std::end(args)) {
      auto encrypted_response = util::from_hex_vec(response_it->second, true);
      serverchallengeresp(sess_it->second, tree, encrypted_response);
    } else if (const auto secret_it = args.find("clientpairingsecret"); secret_it != std::end(args)) {
      auto pairingsecret = util::from_hex_vec(secret_it->second, true);
      clientpairingsecret(sess_it->second, tree, pairingsecret);
      pairing_complete = true;
    } else {
      fail_pair(sess_it->second, tree, "Invalid pairing request");
    }

    if (pairing_complete || sess_it->second.failed) {
      map_id_sess.erase(sess_it);
    }
  }

  bool pin(const std::string_view pairing_id, const std::string &pin, std::string name) {
    if (!is_valid_pairing_id(pairing_id) || !is_valid_pairing_pin(pin) || !is_valid_pairing_name(name)) {
      return false;
    }

    std::shared_ptr<pairing_completion_t> completion;
    auto completion_deadline = std::chrono::steady_clock::time_point::min();
    {
      std::scoped_lock lock {map_id_sess_mutex()};
      const auto now = std::chrono::steady_clock::now();
      expire_pair_sessions_unlocked(now);
      const auto sess_it = std::ranges::find_if(map_id_sess, [&](const auto &entry) {
        return entry.second.last_phase == PAIR_PHASE::NONE && entry.second.async_insert_pin.id == pairing_id;
      });
      if (sess_it == map_id_sess.end()) {
        return false;
      }

      auto &sess = sess_it->second;
      pt::ptree tree;
      getservercert(sess, tree, pin);
      if (!sess.failed) {
        sess.client.name = std::move(name);
      }

      if (!write_pairing_response(sess, tree) || sess.failed) {
        complete_pairing(sess, false);
        map_id_sess.erase(sess_it);
        return false;
      }

      completion = sess.completion;
      completion_deadline = std::min(sess.async_insert_pin.expires_at, now + config::stream.ping_timeout);
    }

    {
      std::unique_lock lock {completion->mutex};
      if (completion->condition.wait_until(lock, completion_deadline, [&completion]() {
            return completion->result.has_value();
          })) {
        return *completion->result;
      }
    }

    std::scoped_lock lock {map_id_sess_mutex()};
    if (const auto sess_it = std::ranges::find_if(map_id_sess, [&](const auto &entry) {
          return entry.second.async_insert_pin.id == pairing_id && entry.second.completion == completion;
        });
        sess_it != map_id_sess.end()) {
      complete_pairing(sess_it->second, false);
      map_id_sess.erase(sess_it);
    }
    return false;
  }

  uint32_t get_codec_mode_flags() {
    const auto &modes = video::probed_codec_modes();
    uint32_t codec_mode_flags = modes.h264 ? SCM_H264 : 0;
    if (modes.h264 && video::last_encoder_probe_supported_yuv444_for_codec[0]) {
      codec_mode_flags |= SCM_H264_HIGH8_444;
    }
    if (video::active_hevc_mode >= 2) {
      codec_mode_flags |= SCM_HEVC;
      if (video::last_encoder_probe_supported_yuv444_for_codec[1]) {
        codec_mode_flags |= SCM_HEVC_REXT8_444;
      }
    }
    if ((video::active_hevc_mode == 3 || video::active_hevc_mode == 5) && video::last_encoder_probe_supported_dynamic_range_for_codec[1]) {
      codec_mode_flags |= SCM_HEVC_MAIN10;
    }
    if ((video::active_hevc_mode == 4 || video::active_hevc_mode == 5) && video::last_encoder_probe_supported_dynamic_range_yuv444_for_codec[1]) {
      codec_mode_flags |= SCM_HEVC_REXT10_444;
    }

    if (video::active_av1_mode >= 2) {
      codec_mode_flags |= SCM_AV1_MAIN8;
      if (video::last_encoder_probe_supported_yuv444_for_codec[2]) {
        codec_mode_flags |= SCM_AV1_HIGH8_444;
      }
    }
    if ((video::active_av1_mode == 3 || video::active_av1_mode == 5) && video::last_encoder_probe_supported_dynamic_range_for_codec[2]) {
      codec_mode_flags |= SCM_AV1_MAIN10;
    }
    if ((video::active_av1_mode == 4 || video::active_av1_mode == 5) && video::last_encoder_probe_supported_dynamic_range_yuv444_for_codec[2]) {
      codec_mode_flags |= SCM_AV1_HIGH10_444;
    }
    if (modes.mpeg2 >= 2) {
      codec_mode_flags |= SCM_MPEG2;
    }
    if (modes.h263p == 2) {
      codec_mode_flags |= SCM_H263P;
    }
    return codec_mode_flags;
  }

  /**
   * @brief Build the GameStream server-info response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void serverinfo(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    int pair_status = 0;
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      auto args = request->parse_query_string();
      auto clientID = args.find("uniqueid"s);

      if (clientID != std::end(args)) {
        pair_status = 1;
      }
    }

    auto local_endpoint = request->local_endpoint();

    pt::ptree tree;

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.hostname", config::nvhttp.sunshine_name);

    tree.put("root.appversion", VERSION);
    tree.put("root.GfeVersion", GFE_VERSION);
    tree.put("root.uniqueid", http::unique_id);
    tree.put("root.HttpsPort", net::map_port(PORT_HTTPS));
    tree.put("root.ExternalPort", net::map_port(PORT_HTTP));
    tree.put("root.MaxLumaPixelsHEVC", video::active_hevc_mode > 1 ? "1869449984" : "0");

    // Only include the MAC address for requests sent from paired clients over HTTPS.
    // For HTTP requests, use a placeholder MAC address that Moonlight knows to ignore.
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      tree.put("root.mac", platf::get_mac_address(net::addr_to_normalized_string(local_endpoint.address())));
    } else {
      tree.put("root.mac", "00:00:00:00:00:00");
    }

    // Moonlight clients track LAN IPv6 addresses separately from LocalIP which is expected to
    // always be an IPv4 address. If we return that same IPv6 address here, it will clobber the
    // stored LAN IPv4 address. To avoid this, we need to return an IPv4 address in this field
    // when we get a request over IPv6.
    //
    // HACK: We should return the IPv4 address of local interface here, but we don't currently
    // have that implemented. For now, we will emulate the behavior of GFE+GS-IPv6-Forwarder,
    // which returns 127.0.0.1 as LocalIP for IPv6 connections. Moonlight clients with IPv6
    // support know to ignore this bogus address.
    if (local_endpoint.address().is_v6() && !local_endpoint.address().to_v6().is_v4_mapped()) {
      tree.put("root.LocalIP", "127.0.0.1");
    } else {
      tree.put("root.LocalIP", net::addr_to_normalized_string(local_endpoint.address()));
    }

    const uint32_t codec_mode_flags = get_codec_mode_flags();
    tree.put("root.ServerCodecModeSupport", codec_mode_flags);

    if (!config::nvhttp.external_ip.empty()) {
      tree.put("root.ExternalIP", config::nvhttp.external_ip);
    }

    auto current_appid = proc::proc.running();
    tree.put("root.PairStatus", pair_status);
    tree.put("root.currentgame", current_appid);
    tree.put("root.state", current_appid > 0 ? "SUNSHINE_SERVER_BUSY" : "SUNSHINE_SERVER_FREE");

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());
    response->close_connection_after_response = true;
  }

  nlohmann::json get_all_clients() {
    nlohmann::json named_cert_nodes = nlohmann::json::array();
    std::lock_guard lock {client_auth_mutex()};
    for (const auto &named_cert : client_root.named_devices) {
      nlohmann::json named_cert_node;
      named_cert_node["name"] = named_cert.name;
      named_cert_node["uuid"] = named_cert.uuid;
      named_cert_node["enabled"] = named_cert.enabled;
      named_cert_node["require_accept"] = named_cert.require_accept;
      named_cert_nodes.push_back(named_cert_node);
    }

    return named_cert_nodes;
  }

  namespace {
    /**
     * @brief Held reconnect approval state for a paired Moonlight client.
     */
    struct pending_reconnect_entry_t {
      std::string id;  ///< Unguessable hexadecimal approval identifier.
      std::string client_uuid;  ///< Persistent UUID of the paired client.
      std::string name;  ///< Friendly paired-client name.
      std::string address;  ///< Network address of the connecting client.
      std::string action;  ///< GameStream endpoint action ("launch" or "resume").
      resp_https_t response;  ///< Held HTTPS response completed on resolution or timeout.
      std::function<void(resp_https_t)> on_approve;  ///< Continuation executed when approved.
      std::shared_ptr<boost::asio::steady_timer> timer;  ///< Optional deadline timer on the HTTPS I/O context.
      std::chrono::steady_clock::time_point expires_at = std::chrono::steady_clock::time_point::max();  ///< Monotonic expiration deadline.
    };

    /**
     * @brief Access the mutex protecting pending reconnect approval requests.
     *
     * @return Mutex serializing pending reconnect request state.
     */
    std::mutex &reconnect_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    /**
     * @brief Access the condition variable notified when pending reconnect requests change.
     *
     * @return Condition variable signaled after queueing a new reconnect request.
     */
    std::condition_variable &reconnect_condition() {
      static std::condition_variable cv;
      return cv;
    }

    /**
     * @brief Access in-memory storage of pending reconnect approval requests.
     *
     * @return Vector of pending reconnect entries in insertion order.
     */
    std::vector<pending_reconnect_entry_t> &pending_reconnect_entries() {
      static std::vector<pending_reconnect_entry_t> entries;
      return entries;
    }

    /**
     * @brief Access the mutex protecting per-request verified client certificates.
     *
     * @return Mutex serializing request-to-certificate associations.
     */
    std::mutex &verified_request_certs_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    /**
     * @brief Access weak request-to-certificate mappings recorded after TLS verification.
     *
     * @return Active request certificate associations.
     */
    std::vector<std::pair<std::weak_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Request>, std::string>> &verified_request_certs() {
      static std::vector<std::pair<std::weak_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Request>, std::string>> entries;
      return entries;
    }

    /**
     * @brief Record the verified client certificate PEM for an active HTTPS request.
     *
     * @param request Active HTTPS request owned by the session.
     * @param cert_pem Canonical PEM-encoded client certificate.
     */
    void store_verified_request_cert(const req_https_t &request, std::string cert_pem) {
      if (!request || cert_pem.empty()) {
        return;
      }

      std::lock_guard lock {verified_request_certs_mutex()};
      auto &entries = verified_request_certs();
      std::erase_if(entries, [&request](const auto &entry) {
        const auto locked = entry.first.lock();
        return !locked || locked.get() == request.get();
      });
      entries.emplace_back(request, std::move(cert_pem));
    }

    /**
     * @brief Look up the verified client certificate PEM associated with an HTTPS request.
     *
     * @param request HTTPS request being processed.
     * @return Canonical PEM-encoded client certificate, or fallback last verified cert.
     */
    std::string find_verified_request_cert(const req_https_t &request) {
      {
        std::lock_guard lock {verified_request_certs_mutex()};
        auto &entries = verified_request_certs();
        for (auto it = entries.begin(); it != entries.end();) {
          const auto locked = it->first.lock();
          if (!locked) {
            it = entries.erase(it);
            continue;
          }
          if (locked.get() == request.get()) {
            return it->second;
          }
          ++it;
        }
      }

      std::lock_guard auth_lock {client_auth_mutex()};
      return last_verified_client_cert;
    }

    /**
     * @brief Look up a persisted paired-client record by canonical PEM certificate.
     *
     * @param cert_pem Canonical PEM-encoded client certificate.
     * @return Matching paired-client record copy, or `std::nullopt` when absent.
     */
    std::optional<named_cert_t> find_client_by_cert(const std::string_view cert_pem) {
      if (cert_pem.empty()) {
        return std::nullopt;
      }

      std::lock_guard lock {client_auth_mutex()};
      for (const auto &named_cert : client_root.named_devices) {
        if (named_cert.cert == cert_pem) {
          return named_cert;
        }
      }
      return std::nullopt;
    }

    /**
     * @brief Look up a persisted paired-client record by persistent UUID.
     *
     * @param uuid Persistent paired-client UUID.
     * @return Matching paired-client record copy, or `std::nullopt` when absent.
     */
    std::optional<named_cert_t> find_client_by_uuid(const std::string_view uuid) {
      std::lock_guard lock {client_auth_mutex()};
      for (const auto &named_cert : client_root.named_devices) {
        if (named_cert.uuid == uuid) {
          return named_cert;
        }
      }
      return std::nullopt;
    }

    /**
     * @brief Write an XML failure response to a held reconnect request and close its connection.
     *
     * @param entry Held reconnect request whose response will be completed.
     * @param status_code GameStream XML status code.
     * @param status_message Human-readable status message returned to Moonlight.
     */
    void write_reconnect_failure_response(
      pending_reconnect_entry_t &entry,
      const int status_code,
      const std::string_view status_message
    ) {
      if (entry.timer) {
        entry.timer->cancel();
        entry.timer.reset();
      }
      if (!entry.response) {
        return;
      }

      pt::ptree tree;
      tree.put("root.<xmlattr>.status_code", status_code);
      tree.put("root.<xmlattr>.status_message", std::string {status_message});
      if (entry.action == "resume"sv) {
        tree.put("root.resume", 0);
      } else {
        tree.put("root.gamesession", 0);
      }

      std::ostringstream data;
      pt::write_xml(data, tree);
      entry.response->close_connection_after_response = true;
      entry.response->write(data.str());
      entry.response.reset();
    }

    /**
     * @brief Collect expired pending reconnect entries while `reconnect_mutex()` is held.
     *
     * @param now Monotonic timestamp used to evaluate deadlines.
     * @return Extracted expired entries whose responses should be completed outside the lock.
     */
    std::vector<pending_reconnect_entry_t> take_expired_reconnects_unlocked(
      const std::chrono::steady_clock::time_point now
    ) {
      std::vector<pending_reconnect_entry_t> expired;
      auto &entries = pending_reconnect_entries();
      for (auto it = entries.begin(); it != entries.end();) {
        if (it->expires_at > now) {
          ++it;
          continue;
        }
        expired.push_back(std::move(*it));
        it = entries.erase(it);
      }
      return expired;
    }

    /**
     * @brief Complete a batch of expired reconnect entries with a 408 timeout XML response.
     *
     * @param expired Extracted expired reconnect entries.
     */
    void complete_expired_reconnects(std::vector<pending_reconnect_entry_t> &expired) {
      for (auto &entry : expired) {
        write_reconnect_failure_response(entry, 408, "Connection request timed out waiting for host approval");
      }
    }

    /**
     * @brief Cancel and reject any pending reconnect requests belonging to a specific client UUID.
     *
     * @param uuid Persistent UUID of the disabled or unpaired client.
     */
    void cancel_pending_reconnects_for_client(const std::string_view uuid) {
      std::vector<pending_reconnect_entry_t> cancelled;
      {
        std::lock_guard lock {reconnect_mutex()};
        auto &entries = pending_reconnect_entries();
        for (auto it = entries.begin(); it != entries.end();) {
          if (it->client_uuid == uuid) {
            cancelled.push_back(std::move(*it));
            it = entries.erase(it);
          } else {
            ++it;
          }
        }
      }

      for (auto &entry : cancelled) {
        write_reconnect_failure_response(entry, 403, "Client is no longer authorized to connect");
      }
    }

    /**
     * @brief Cancel and reject all pending reconnect requests.
     */
    void cancel_all_pending_reconnects() {
      std::vector<pending_reconnect_entry_t> cancelled;
      {
        std::lock_guard lock {reconnect_mutex()};
        cancelled.swap(pending_reconnect_entries());
      }

      for (auto &entry : cancelled) {
        write_reconnect_failure_response(entry, 403, "Connection request cancelled");
      }
    }

    /**
     * @brief Queue a reconnect approval request for a paired client.
     *
     * Supersedes any earlier pending reconnect request from the same client UUID.
     *
     * @param client Persisted paired-client metadata.
     * @param address Remote client network address.
     * @param action GameStream action ("launch" or "resume").
     * @param response Held HTTPS response object.
     * @param io_service Optional HTTPS server I/O context used to arm an automatic expiration timer.
     * @param on_approve Continuation executed if the operator approves the request.
     * @return `true` when queued; `false` when the bounded pending queue is full.
     */
    bool enqueue_reconnect_approval(
      const named_cert_t &client,
      std::string address,
      std::string action,
      resp_https_t response,
      const std::shared_ptr<boost::asio::io_context> &io_service,
      std::function<void(resp_https_t)> on_approve
    ) {
      std::vector<pending_reconnect_entry_t> expired;
      std::optional<pending_reconnect_entry_t> superseded;
      bool queued = false;
      {
        std::lock_guard lock {reconnect_mutex()};
        const auto now = std::chrono::steady_clock::now();
        expired = take_expired_reconnects_unlocked(now);

        auto &entries = pending_reconnect_entries();
        if (const auto existing_it = std::ranges::find(entries, client.uuid, &pending_reconnect_entry_t::client_uuid);
            existing_it != entries.end()) {
          superseded = std::move(*existing_it);
          entries.erase(existing_it);
        }

        if (entries.size() < MAX_PENDING_RECONNECT_REQUESTS) {
          pending_reconnect_entry_t entry {
            .id = uuid_util::uuid_t::generate().string(),
            .client_uuid = client.uuid,
            .name = client.name,
            .address = std::move(address),
            .action = std::move(action),
            .response = std::move(response),
            .on_approve = std::move(on_approve),
            .timer = nullptr,
            .expires_at = now + RECONNECT_APPROVAL_TIMEOUT,
          };

          if (io_service) {
            entry.timer = std::make_shared<boost::asio::steady_timer>(*io_service, RECONNECT_APPROVAL_TIMEOUT);
            entry.timer->async_wait([](const boost::system::error_code &ec) {
              if (!ec) {
                expire_pending_reconnects();
              }
            });
          }

          entries.push_back(std::move(entry));
          queued = true;
        }
      }

      complete_expired_reconnects(expired);
      if (superseded) {
        write_reconnect_failure_response(*superseded, 409, "Superseded by a newer connection request");
      }
      if (queued) {
        reconnect_condition().notify_all();
      }
      return queued;
    }
  }  // namespace

  void expire_pending_reconnects(const std::chrono::steady_clock::time_point now) {
    std::vector<pending_reconnect_entry_t> expired;
    {
      std::lock_guard lock {reconnect_mutex()};
      expired = take_expired_reconnects_unlocked(now);
    }
    complete_expired_reconnects(expired);
  }

  std::vector<pending_reconnect_t> get_pending_reconnects() {
    std::vector<pending_reconnect_entry_t> expired;
    std::vector<pending_reconnect_t> result;
    {
      std::lock_guard lock {reconnect_mutex()};
      expired = take_expired_reconnects_unlocked(std::chrono::steady_clock::now());
      const auto &entries = pending_reconnect_entries();
      result.reserve(entries.size());
      for (const auto &entry : entries) {
        result.push_back({
          .id = entry.id,
          .client_uuid = entry.client_uuid,
          .name = entry.name,
          .address = entry.address,
          .action = entry.action,
        });
      }
    }
    complete_expired_reconnects(expired);
    return result;
  }

  bool resolve_pending_reconnect(const std::string_view request_id, const bool approve) {
    if (request_id.empty()) {
      return false;
    }

    std::vector<pending_reconnect_entry_t> expired;
    std::optional<pending_reconnect_entry_t> matched;
    {
      std::lock_guard lock {reconnect_mutex()};
      expired = take_expired_reconnects_unlocked(std::chrono::steady_clock::now());
      auto &entries = pending_reconnect_entries();
      const auto it = std::ranges::find(entries, request_id, &pending_reconnect_entry_t::id);
      if (it != entries.end()) {
        matched = std::move(*it);
        entries.erase(it);
      }
    }
    complete_expired_reconnects(expired);

    if (!matched) {
      return false;
    }

    if (matched->timer) {
      matched->timer->cancel();
      matched->timer.reset();
    }

    if (!approve) {
      write_reconnect_failure_response(*matched, 403, "Connection request was denied by the host");
      return true;
    }

    const auto client = find_client_by_uuid(matched->client_uuid);
    if (!client || !client->enabled) {
      write_reconnect_failure_response(*matched, 403, "Client is no longer authorized to connect");
      return false;
    }

    if (matched->on_approve) {
      matched->on_approve(std::move(matched->response));
    }
    return true;
  }

  /**
   * @brief Build the GameStream application list response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void applist(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);
    proc::refresh(config::stream.file_apps);

    pt::ptree tree;

    auto g = util::fail_guard([&tree, &response]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto &apps = tree.add_child("root", pt::ptree {});

    apps.put("<xmlattr>.status_code", 200);

    for (auto &proc : proc::proc.get_apps()) {
      pt::ptree app;

      app.put("IsHdrSupported"s, video::active_hevc_mode >= 3 ? 1 : 0);
      app.put("AppTitle"s, proc.name);
      app.put("ID", proc.id);

      apps.push_back(std::make_pair("App", app));
    }
  }

  /**
   * @brief Complete an authorized GameStream application launch and write the XML response.
   *
   * @param host_audio Host audio state updated from launch parameters.
   * @param response HTTPS response object to populate.
   * @param request HTTPS request data from the client.
   * @param args Parsed request query parameters.
   * @param client_cert Verified PEM certificate for the launching client.
   * @param client_name Friendly name of the launching client.
   */
  void execute_launch_approved(
    bool &host_audio,
    resp_https_t response,
    req_https_t request,
    const args_t &args,
    const std::string &client_cert,
    const std::string &client_name
  ) {
    pt::ptree tree;
    bool revert_display_configuration {false};
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;

      if (revert_display_configuration) {
        display_device::revert_configuration();
      }
    });

    auto appid = util::from_view(get_arg(args, "appid"));

    auto current_appid = proc::proc.running();
    if (current_appid > 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "An app is already running on this host");

      return;
    }

    host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
    auto launch_session = make_launch_session(host_audio, args, client_cert, client_name);

    if (rtsp_stream::session_count() == 0) {
      // The display should be restored in case something fails as there are no other sessions.
      revert_display_configuration = true;

      // We want to prepare display only if there are no active sessions at
      // the moment. This should be done before probing encoders as it could
      // change the active displays.
      display_device::configure_display(config::video, *launch_session);

      // Probe encoders again before streaming to ensure our chosen
      // encoder matches the active GPU (which could have changed
      // due to hotplugging, driver crash, primary monitor change,
      // or any number of other factors).
      if (video::probe_encoders()) {
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Failed to initialize video capture/encoding. Is a display connected and turned on?");
        tree.put("root.gamesession", 0);

        return;
      }
    }

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);

      return;
    }

    if (appid > 0) {
      auto err = proc::proc.execute((int) appid, launch_session);
      if (err) {
        tree.put("root.<xmlattr>.status_code", err);
        tree.put("root.<xmlattr>.status_message", "Failed to start the specified application");
        tree.put("root.gamesession", 0);

        return;
      }
    }

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put(
      "root.sessionUrl0",
      std::format(
        "{}{}:{}",
        launch_session->rtsp_url_scheme,
        net::addr_to_url_escaped_string(request->local_endpoint().address()),
        static_cast<int>(net::map_port(rtsp_stream::RTSP_SETUP_PORT))
      )
    );
    tree.put("root.gamesession", 1);

    rtsp_stream::launch_session_raise(launch_session);

    // Stream was started successfully, we will revert the config when the app or session terminates
    revert_display_configuration = false;
  }

  /**
   * @brief Launch the requested application for a GameStream session, holding for approval when configured.
   *
   * @param host_audio Host audio.
   * @param response HTTP response object to populate or hold.
   * @param request HTTP request data from the client.
   * @param io_service Optional HTTPS server I/O context for expiration timers.
   * @param post_to_server Optional scheduler that posts approved continuations back onto the HTTPS server thread.
   */
  void launch(
    bool &host_audio,
    resp_https_t response,
    req_https_t request,
    const std::shared_ptr<boost::asio::io_context> &io_service = nullptr,
    const std::function<void(std::function<void()>)> &post_to_server = {}
  ) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args) ||
      args.find("localAudioPlayMode"s) == std::end(args) ||
      args.find("appid"s) == std::end(args)
    ) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required launch parameter");

      return;
    }

    if (proc::proc.running() > 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "An app is already running on this host");

      return;
    }

    const auto client_cert = find_verified_request_cert(request);
    const auto client_record = find_client_by_cert(client_cert);
    if (client_record && !client_record->enabled) {
      tree.put("root.gamesession", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Client is disabled");
      return;
    }

    const std::string client_name = client_record ? client_record->name : last_verified_client_name;
    if (client_record && client_record->require_accept) {
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      const bool queued = enqueue_reconnect_approval(
        *client_record,
        std::move(address),
        "launch"s,
        response,
        io_service,
        [&host_audio, request, args = std::move(args), client_cert, client_name, post_to_server](resp_https_t approved_response) mutable {
          auto work = [&host_audio,
                       approved_response = std::move(approved_response),
                       request = std::move(request),
                       args = std::move(args),
                       client_cert = std::move(client_cert),
                       client_name = std::move(client_name)]() mutable {
            execute_launch_approved(host_audio, std::move(approved_response), std::move(request), args, client_cert, client_name);
          };
          if (post_to_server) {
            post_to_server(std::move(work));
          } else {
            work();
          }
        }
      );
      if (!queued) {
        tree.put("root.gamesession", 0);
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Too many pending connection approval requests");
        return;
      }

      g.disable();
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
      system_tray::update_tray_require_reconnect(client_record->name);
#endif
      return;
    }

    g.disable();
    execute_launch_approved(host_audio, std::move(response), std::move(request), args, client_cert, client_name);
  }

  /**
   * @brief Complete an authorized GameStream session resume and write the XML response.
   *
   * @param host_audio Host audio state updated when applicable.
   * @param response HTTPS response object to populate.
   * @param request HTTPS request data from the client.
   * @param args Parsed request query parameters.
   * @param client_cert Verified PEM certificate for the resuming client.
   * @param client_name Friendly name of the resuming client.
   */
  void execute_resume_approved(
    bool &host_audio,
    resp_https_t response,
    req_https_t request,
    const args_t &args,
    const std::string &client_cert,
    const std::string &client_name
  ) {
    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto current_appid = proc::proc.running();
    if (current_appid == 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message", "No running app to resume");

      return;
    }

    // Newer Moonlight clients send localAudioPlayMode on /resume too,
    // so we should use it if it's present in the args and there are
    // no active sessions we could be interfering with.
    const bool no_active_sessions {rtsp_stream::session_count() == 0};
    if (no_active_sessions && args.find("localAudioPlayMode"s) != std::end(args)) {
      host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
    }
    const auto launch_session = make_launch_session(host_audio, args, client_cert, client_name);

    if (no_active_sessions) {
      // We want to prepare display only if there are no active sessions at
      // the moment. This should be done before probing encoders as it could
      // change the active displays.
      display_device::configure_display(config::video, *launch_session);

      // Probe encoders again before streaming to ensure our chosen
      // encoder matches the active GPU (which could have changed
      // due to hotplugging, driver crash, primary monitor change,
      // or any number of other factors).
      if (video::probe_encoders()) {
        tree.put("root.resume", 0);
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Failed to initialize video capture/encoding. Is a display connected and turned on?");

        return;
      }
    }

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);

      return;
    }

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put(
      "root.sessionUrl0",
      std::format(
        "{}{}:{}",
        launch_session->rtsp_url_scheme,
        net::addr_to_url_escaped_string(request->local_endpoint().address()),
        static_cast<int>(net::map_port(rtsp_stream::RTSP_SETUP_PORT))
      )
    );
    tree.put("root.resume", 1);

    rtsp_stream::launch_session_raise(launch_session);
  }

  /**
   * @brief Resume an existing GameStream session, holding for approval when configured.
   *
   * @param host_audio Host audio.
   * @param response HTTP response object to populate or hold.
   * @param request HTTP request data from the client.
   * @param io_service Optional HTTPS server I/O context for expiration timers.
   * @param post_to_server Optional scheduler that posts approved continuations back onto the HTTPS server thread.
   */
  void resume(
    bool &host_audio,
    resp_https_t response,
    req_https_t request,
    const std::shared_ptr<boost::asio::io_context> &io_service = nullptr,
    const std::function<void(std::function<void()>)> &post_to_server = {}
  ) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto current_appid = proc::proc.running();
    if (current_appid == 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message", "No running app to resume");

      return;
    }

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args)
    ) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required resume parameter");

      return;
    }

    const auto client_cert = find_verified_request_cert(request);
    const auto client_record = find_client_by_cert(client_cert);
    if (client_record && !client_record->enabled) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Client is disabled");
      return;
    }

    const std::string client_name = client_record ? client_record->name : last_verified_client_name;
    if (client_record && client_record->require_accept) {
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      const bool queued = enqueue_reconnect_approval(
        *client_record,
        std::move(address),
        "resume"s,
        response,
        io_service,
        [&host_audio, request, args = std::move(args), client_cert, client_name, post_to_server](resp_https_t approved_response) mutable {
          auto work = [&host_audio,
                       approved_response = std::move(approved_response),
                       request = std::move(request),
                       args = std::move(args),
                       client_cert = std::move(client_cert),
                       client_name = std::move(client_name)]() mutable {
            execute_resume_approved(host_audio, std::move(approved_response), std::move(request), args, client_cert, client_name);
          };
          if (post_to_server) {
            post_to_server(std::move(work));
          } else {
            work();
          }
        }
      );
      if (!queued) {
        tree.put("root.resume", 0);
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Too many pending connection approval requests");
        return;
      }

      g.disable();
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
      system_tray::update_tray_require_reconnect(client_record->name);
#endif
      return;
    }

    g.disable();
    execute_resume_approved(host_audio, std::move(response), std::move(request), args, client_cert, client_name);
  }

  /**
   * @brief Check whether cel.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void cancel(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&tree, &response]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    const auto client_cert = find_verified_request_cert(request);
    const auto client_record = find_client_by_cert(client_cert);
    if (client_record && !client_record->enabled) {
      tree.put("root.cancel", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Client is disabled");
      return;
    }
    if (client_record && client_record->require_accept) {
      tree.put("root.cancel", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Client is not permitted to cancel the session");
      return;
    }

    tree.put("root.cancel", 1);
    tree.put("root.<xmlattr>.status_code", 200);

    rtsp_stream::terminate_sessions();

    if (proc::proc.running() > 0) {
      proc::proc.terminate();
    }

    // The config needs to be reverted regardless of whether "proc::proc.terminate()" was called or not.
    display_device::revert_configuration();
  }

  /**
   * @brief Return an application asset requested by the client.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void appasset(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    auto args = request->parse_query_string();
    auto app_image = proc::proc.get_app_image((int) util::from_view(get_arg(args, "appid")));

    std::ifstream in(app_image, std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
    response->close_connection_after_response = true;
  }

  void setup(const std::string &pkey, const std::string &cert) {
    conf_intern.pkey = pkey;
    conf_intern.servercert = cert;
  }

  /**
   * @brief Check whether a paired client certificate is allowed to connect and retrieve its friendly name.
   *
   * @param cert_pem PEM-encoded client certificate to look up.
   * @return Pair of (bool enabled, string name) where "enabled" is True when the client certificate belongs to an
             enabled device and "name" is the friendly client name set during pairing.
   */
  std::pair<bool, std::string> get_client_status(const std::string_view cert_pem);

  void start() {
    platf::set_thread_name("nvhttp");
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_http = net::map_port(PORT_HTTP);
    auto port_https = net::map_port(PORT_HTTPS);
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    bool clean_slate = config::sunshine.flags[config::flag::FRESH_STATE];

    if (!clean_slate) {
      load_state();
    }

    auto pkey = file_handler::read_file(config::nvhttp.pkey.c_str());
    auto cert = file_handler::read_file(config::nvhttp.cert.c_str());
    setup(pkey, cert);

    // resume doesn't always get the parameter "localAudioPlayMode"
    // launch will store it in host_audio
    bool host_audio {};

    https_server_t https_server {config::nvhttp.cert, config::nvhttp.pkey};
    http_server_t http_server;

    // Verify certificates after establishing connection
    https_server.verify = [](SSL *ssl) {
      crypto::x509_t x509 {
#if OPENSSL_VERSION_MAJOR >= 3
        SSL_get1_peer_certificate(ssl)
#else
        SSL_get_peer_certificate(ssl)
#endif
      };
      if (!x509) {
        BOOST_LOG(info) << "unknown -- denied"sv;
        return 0;
      }

      int verified = 0;

      auto fg = util::fail_guard([&]() {
        std::array<char, 256> subject_name;

        X509_NAME_oneline(X509_get_subject_name(x509.get()), subject_name.data(), subject_name.size());

        BOOST_LOG(debug) << subject_name.data() << " -- "sv << (verified ? "verified"sv : "denied"sv);
      });

      std::lock_guard lock {client_auth_mutex()};
      auto err_str = verify_client_certificate(x509.get());
      if (err_str) {
        BOOST_LOG(warning) << "SSL Verification error :: "sv << err_str;

        return verified;
      }

      // Check if this client is enabled
      auto pem = crypto::pem(x509);
      auto [enabled, client_name] = get_client_status(pem);
      if (!enabled) {
        BOOST_LOG(info) << "Client is disabled -- denied"sv;
        return verified;
      }

      last_verified_client_cert = pem;
      last_verified_client_name = client_name;
      verified = 1;

      return verified;
    };

    https_server.on_verified = [](const req_https_t &request, SSL *ssl) {
      crypto::x509_t x509 {
#if OPENSSL_VERSION_MAJOR >= 3
        SSL_get1_peer_certificate(ssl)
#else
        SSL_get_peer_certificate(ssl)
#endif
      };
      if (x509) {
        store_verified_request_cert(request, crypto::pem(x509));
      }
    };

    https_server.on_verify_failed = [](resp_https_t resp, req_https_t req) {
      pt::ptree tree;
      auto g = util::fail_guard([&tree, &resp]() {
        std::ostringstream data;

        pt::write_xml(data, tree);
        resp->write(data.str());
        resp->close_connection_after_response = true;
      });

      tree.put("root.<xmlattr>.status_code"s, 401);
      tree.put("root.<xmlattr>.query"s, req->path);
      tree.put("root.<xmlattr>.status_message"s, "The client is not authorized. Certificate verification failed."s);
    };

    auto post_to_https_server = [&https_server](std::function<void()> callback) {
      https_server.post_guarded(std::move(callback));
    };

    https_server.default_resource["GET"] = not_found<SunshineHTTPS>;
    https_server.resource["^/serverinfo$"]["GET"] = serverinfo<SunshineHTTPS>;
    https_server.resource["^/pair$"]["GET"] = [](auto resp, auto req) {
      pair<SunshineHTTPS>(resp, req);
    };
    https_server.resource["^/applist$"]["GET"] = applist;
    https_server.resource["^/appasset$"]["GET"] = appasset;
    https_server.resource["^/launch$"]["GET"] = [&host_audio, &https_server, post_to_https_server](auto resp, auto req) {
      launch(host_audio, resp, req, https_server.io_service, post_to_https_server);
    };
    https_server.resource["^/resume$"]["GET"] = [&host_audio, &https_server, post_to_https_server](auto resp, auto req) {
      resume(host_audio, resp, req, https_server.io_service, post_to_https_server);
    };
    https_server.resource["^/cancel$"]["GET"] = cancel;

    https_server.config.reuse_address = true;
    https_server.config.address = net::get_bind_address(address_family);
    https_server.config.port = port_https;

    http_server.default_resource["GET"] = not_found<SimpleWeb::HTTP>;
    http_server.resource["^/serverinfo$"]["GET"] = serverinfo<SimpleWeb::HTTP>;
    http_server.resource["^/pair$"]["GET"] = [](auto resp, auto req) {
      pair<SimpleWeb::HTTP>(resp, req);
    };

    http_server.config.reuse_address = true;
    http_server.config.address = net::get_bind_address(address_family);
    http_server.config.port = port_http;

    auto accept_and_run = [&](auto *web_server) {
      try {
        std::string name = "nvhttp::" + std::to_string(web_server->config.port);
        platf::set_thread_name(name);
        web_server->start();
      } catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling http_server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start http server on ports ["sv << port_https << ", "sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::jthread ssl {accept_and_run, &https_server};
    std::jthread tcp {accept_and_run, &http_server};

    // Wait for any event
    shutdown_event->view();

    cancel_all_pending_reconnects();
    https_server.stop();
    http_server.stop();

    ssl.join();
    tcp.join();
  }

  void erase_all_clients() {
    {
      std::lock_guard lock {client_auth_mutex()};
      client_root = {};
      cert_chain.clear();
      save_state();
    }
    cancel_all_pending_reconnects();
  }

  bool unpair_client(const std::string_view uuid) {
    bool removed = false;
    {
      std::lock_guard lock {client_auth_mutex()};
      for (auto it = client_root.named_devices.begin(); it != client_root.named_devices.end();) {
        if ((*it).uuid == uuid) {
          it = client_root.named_devices.erase(it);
          removed = true;
        } else {
          ++it;
        }
      }

      rebuild_client_cert_chain();
      save_state();
    }

    if (removed) {
      cancel_pending_reconnects_for_client(uuid);
    }
    return removed;
  }

  bool set_client_enabled(const std::string_view uuid, bool enabled) {
    bool updated = false;
    {
      std::lock_guard lock {client_auth_mutex()};
      for (auto &named_cert : client_root.named_devices) {
        if (named_cert.uuid == uuid) {
          named_cert.enabled = enabled;
          rebuild_client_cert_chain();
          save_state();
          updated = true;
          break;
        }
      }
    }

    if (updated && !enabled) {
      cancel_pending_reconnects_for_client(uuid);
    }
    return updated;
  }

  bool set_client_require_accept(const std::string_view uuid, const bool require_accept) {
    std::lock_guard lock {client_auth_mutex()};
    for (auto &named_cert : client_root.named_devices) {
      if (named_cert.uuid == uuid) {
        named_cert.require_accept = require_accept;
        // TODO: I think we need to clean up pending reconnects here if require_accept is false
        save_state();
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Get cert by UUID.
   */
  std::string get_cert_by_uuid(const std::string_view uuid) {
    std::lock_guard lock {client_auth_mutex()};
    for (const auto &named_cert : client_root.named_devices) {
      if (named_cert.uuid == uuid) {
        return named_cert.cert;
      }
    }
    return {};
  }

  /**
   * @brief Check whether a paired client certificate is allowed to connect and return its friendly name.
   */
  std::pair<bool, std::string> get_client_status(const std::string_view cert_pem) {
    const client_t &client = client_root;
    for (const auto &named_cert : client.named_devices) {
      if (named_cert.cert == cert_pem) {
        return {named_cert.enabled, named_cert.name};
      }
    }
    return {true, {}};
  }

#ifdef SUNSHINE_TESTS
  namespace test_support {
    std::unique_ptr<SimpleWeb::ServerBase<SunshineHTTPS>> make_https_server(
      const std::string &certificate_file,
      const std::string &private_key_file,
      std::shared_ptr<SimpleWeb::ScopeRunner> &handler_scope
    ) {
      /**
       * @brief Expose the production HTTPS handler scope to lifetime regression tests.
       */
      class test_https_server_t: public SunshineHTTPSServer {
      public:
        using SunshineHTTPSServer::handler_runner;
        using SunshineHTTPSServer::SunshineHTTPSServer;
      };

      auto server = std::make_unique<test_https_server_t>(certificate_file, private_key_file);
      handler_scope = server->handler_runner;
      return server;
    }

    void pair_http(
      std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response> response,
      std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Request> request
    ) {
      pair<SimpleWeb::HTTP>(std::move(response), std::move(request));
    }

    void reset_client_state() {
      cancel_all_pending_reconnects();
      {
        std::lock_guard cert_lock {verified_request_certs_mutex()};
        verified_request_certs().clear();
      }
      std::lock_guard lock {client_auth_mutex()};
      client_root = {};
      cert_chain.clear();
      last_verified_client_cert.clear();
      last_verified_client_name.clear();
    }

    std::string add_client(const std::string &name, std::string cert, bool enabled) {
      auto uuid = add_authorized_client(name, std::move(cert));
      if (!uuid.empty() && !enabled) {
        set_client_enabled(uuid, false);
      }
      return uuid;
    }

    bool duplicate_client(const std::string_view uuid) {
      std::lock_guard lock {client_auth_mutex()};
      const auto client_it = std::ranges::find(client_root.named_devices, uuid, &named_cert_t::uuid);
      if (client_it == client_root.named_devices.end()) {
        return false;
      }

      auto duplicate = *client_it;
      duplicate.uuid = uuid_util::uuid_t::generate().string();
      client_root.named_devices.emplace_back(std::move(duplicate));
      rebuild_client_cert_chain();
      save_state();
      return true;
    }

    bool authorize_client_certificate(const std::string_view cert) {
      auto certificate = crypto::x509(cert);
      if (!certificate) {
        return false;
      }

      std::lock_guard lock {client_auth_mutex()};
      return verify_client_certificate(certificate.get()) == nullptr;
    }

    bool complete_pairing(const std::string_view pairing_id, const bool success) {
      std::scoped_lock lock {map_id_sess_mutex()};
      const auto sess_it = std::ranges::find_if(map_id_sess, [&](const auto &entry) {
        return entry.second.async_insert_pin.id == pairing_id;
      });
      if (sess_it == map_id_sess.end()) {
        return false;
      }

      nvhttp::complete_pairing(sess_it->second, success);
      map_id_sess.erase(sess_it);
      return true;
    }

    void reload_client_state() {
      load_state();
    }

    std::string enqueue_reconnect_for_testing(
      const std::string_view uuid,
      std::string address,
      std::string action,
      std::function<void()> on_approve
    ) {
      const auto client = find_client_by_uuid(uuid);
      if (!client) {
        return {};
      }

      const bool queued = enqueue_reconnect_approval(
        *client,
        std::move(address),
        std::move(action),
        nullptr,
        nullptr,
        [cb = std::move(on_approve)](resp_https_t) mutable {
          if (cb) {
            cb();
          }
        }
      );
      if (!queued) {
        return {};
      }

      std::lock_guard lock {reconnect_mutex()};
      const auto &entries = pending_reconnect_entries();
      const auto it = std::ranges::find(entries, uuid, &pending_reconnect_entry_t::client_uuid);
      return it != entries.end() ? it->id : std::string {};
    }

    std::unique_ptr<SimpleWeb::ServerBase<SunshineHTTPS>> make_stream_https_server(
      const std::string &certificate_file,
      const std::string &private_key_file,
      bool &host_audio
    ) {
      auto server = std::make_unique<SunshineHTTPSServer>(certificate_file, private_key_file);
      auto *raw_server = server.get();

      server->verify = [](SSL *ssl) {
        crypto::x509_t x509 {
  #if OPENSSL_VERSION_MAJOR >= 3
          SSL_get1_peer_certificate(ssl)
  #else
          SSL_get_peer_certificate(ssl)
  #endif
        };
        if (!x509) {
          return 0;
        }

        std::lock_guard lock {client_auth_mutex()};
        if (verify_client_certificate(x509.get()) != nullptr) {
          return 0;
        }

        auto pem = crypto::pem(x509);
        auto [enabled, client_name] = get_client_status(pem);
        if (!enabled) {
          return 0;
        }

        last_verified_client_cert = pem;
        last_verified_client_name = client_name;
        return 1;
      };

      server->on_verified = [](const req_https_t &request, SSL *ssl) {
        crypto::x509_t x509 {
  #if OPENSSL_VERSION_MAJOR >= 3
          SSL_get1_peer_certificate(ssl)
  #else
          SSL_get_peer_certificate(ssl)
  #endif
        };
        if (x509) {
          store_verified_request_cert(request, crypto::pem(x509));
        }
      };

      server->on_verify_failed = [](resp_https_t resp, req_https_t req) {
        pt::ptree tree;
        tree.put("root.<xmlattr>.status_code"s, 401);
        tree.put("root.<xmlattr>.query"s, req->path);
        tree.put("root.<xmlattr>.status_message"s, "The client is not authorized. Certificate verification failed."s);
        std::ostringstream data;
        pt::write_xml(data, tree);
        resp->write(data.str());
        resp->close_connection_after_response = true;
      };

      auto post_to_https_server = [raw_server](std::function<void()> callback) {
        raw_server->post_guarded(std::move(callback));
      };

      server->resource["^/launch$"]["GET"] = [&host_audio, raw_server, post_to_https_server](auto resp, auto req) {
        launch(host_audio, resp, req, raw_server->io_service, post_to_https_server);
      };
      server->resource["^/resume$"]["GET"] = [&host_audio, raw_server, post_to_https_server](auto resp, auto req) {
        resume(host_audio, resp, req, raw_server->io_service, post_to_https_server);
      };
      server->resource["^/cancel$"]["GET"] = cancel;
      return server;
    }

    std::string wait_for_pending_reconnect_id(
      const std::string_view previous_id,
      const std::chrono::milliseconds timeout
    ) {
      std::unique_lock lock {reconnect_mutex()};
      std::string matched_id;
      reconnect_condition().wait_for(lock, timeout, [&]() {
        const auto &entries = pending_reconnect_entries();
        if (!entries.empty() && entries.front().id != previous_id) {
          matched_id = entries.front().id;
          return true;
        }
        return false;
      });
      return matched_id;
    }
  }  // namespace test_support
#endif
}  // namespace nvhttp
