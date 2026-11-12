#include "catalog/rest/storage/authorization/oauth2.hpp"

#include "duckdb/main/extension_helper.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/json_document.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/common/algorithm.hpp"
#include "duckdb/common/printer.hpp"

#include "iceberg_extension.hpp"
#include "common/iceberg_utils.hpp"
#include "iceberg_logging.hpp"
#include "catalog/rest/iceberg_catalog.hpp"
#include "catalog/rest/api/api_utils.hpp"

#include "rest_catalog/objects/oauth_token_response.hpp"
#include "rest_catalog/objects/oauth_error.hpp"
#include "rest_catalog/objects/json_utils.hpp"

#include <chrono>
#include <thread>

namespace duckdb {

namespace {

//! NOTE: We sadly don't receive the CreateSecretFunction or some other context to deduplicate the recognized options
//! So we use this to deduplicate it instead
static const case_insensitive_map_t<LogicalType> &IcebergSecretOptions() {
	static const case_insensitive_map_t<LogicalType> options {
	    {"client_id", LogicalType::VARCHAR},
	    {"client_secret", LogicalType::VARCHAR},
	    {"uri", LogicalType::VARCHAR},
	    {"endpoint", LogicalType::VARCHAR},
	    {"token", LogicalType::VARCHAR},
	    {"refresh_token", LogicalType::VARCHAR},
	    {"expires_in", LogicalType::INTEGER},
	    {"oauth2_scope", LogicalType::VARCHAR},
	    {"oauth2_server_uri", LogicalType::VARCHAR},
	    {"oauth2_grant_type", LogicalType::VARCHAR},
	    {"oauth2_device_authorization_uri", LogicalType::VARCHAR},
	    {"extra_http_headers", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)}};
	return options;
}

static constexpr const char *DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

static bool IsDeviceCodeGrant(const string &grant_type) {
	return StringUtil::CIEquals(grant_type, "device_code") || StringUtil::CIEquals(grant_type, DEVICE_CODE_GRANT_TYPE);
}

} // namespace

OAuth2Authorization::OAuth2Authorization(AttachedDatabase &db)
    : IcebergAuthorization(db, IcebergAuthorizationType::OAUTH2) {
}

OAuth2Authorization::OAuth2Authorization(AttachedDatabase &db, unique_ptr<const OAuth2Credentials> credentials,
                                         const string &uri, const string &scope)
    : IcebergAuthorization(db, IcebergAuthorizationType::OAUTH2), uri(uri), scope(scope),
      credentials(std::move(credentials)) {
}

//! NOTE: this doesnt use StringUtil::URLEncode(..., escape_slash=true) because of how ' ' (space) is encoded
namespace {

static string XWWWFormUrlEncode(const string &input) {
	string result;
	static const char *HEX_DIGIT = "0123456789ABCDEF";
	for (idx_t i = 0; i < input.size(); i++) {
		char ch = input[i];
		if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' ||
		    ch == '-' || ch == '~' || ch == '.') {
			result += ch;
		} else {
			result += '%';
			result += HEX_DIGIT[static_cast<unsigned char>(ch) >> 4];
			result += HEX_DIGIT[static_cast<unsigned char>(ch) & 15];
		}
	}
	return result;
}

static unique_ptr<OAuth2Credentials> ExtractOAuth2CredentialsFromSecret(const KeyValueSecret &secret) {
	// Extra headers are forwarded to the OAuth2 token endpoint as well, not just to catalog requests (issue #978).
	unordered_map<string, string> extra_http_headers;
	IcebergAuthorization::ParseExtraHttpHeaders(secret.TryGetValue("extra_http_headers"), extra_http_headers);

	auto grant_type = secret.TryGetValue("oauth2_grant_type");
	// Device-code clients are usually public clients without a secret.
	const bool device_code = !grant_type.IsNull() && IsDeviceCodeGrant(grant_type.ToString());

	auto client_id = secret.TryGetValue("client_id");
	auto client_secret = secret.TryGetValue("client_secret");
	unique_ptr<ClientCredentials> client;
	if (!client_id.IsNull() && (device_code || !client_secret.IsNull())) {
		client = make_uniq<ClientCredentials>(client_id.ToString(),
		                                      client_secret.IsNull() ? string() : client_secret.ToString());
	}
	auto refresh_token = secret.TryGetValue("refresh_token");
	if (!refresh_token.IsNull()) {
		if (!client) {
			if (device_code) {
				throw InvalidInputException("Device-code refresh-token credentials require 'client_id'");
			}
			throw InvalidInputException("Refresh-token credentials require both 'client_id' and 'client_secret'");
		}
		auto refresh_credentials = make_uniq<RefreshTokenCredentials>(*client, refresh_token.ToString(), device_code);
		refresh_credentials->extra_http_headers = extra_http_headers;
		return std::move(refresh_credentials);
	}
	if (device_code) {
		// Without a refresh token there is no non-interactive way to renew the token.
		return nullptr;
	}
	if (!grant_type.IsNull() && !grant_type.ToString().empty() &&
	    !StringUtil::CIEquals(grant_type.ToString(), "client_credentials")) {
		throw InvalidInputException("Unsupported OAuth2 grant type '%s'", grant_type.ToString());
	}
	if (client) {
		client->extra_http_headers = extra_http_headers;
	}
	return std::move(client);
}

static const ClientCredentials &GetClientCredentials(const OAuth2Credentials &credentials) {
	switch (credentials.grant_type) {
	case OAuth2GrantType::CLIENT_CREDENTIALS:
		return credentials.Cast<ClientCredentials>();
	case OAuth2GrantType::REFRESH_TOKEN:
		return credentials.Cast<RefreshTokenCredentials>().client_credentials;
	case OAuth2GrantType::DEVICE_CODE:
		return credentials.Cast<DeviceCodeCredentials>().client_credentials;
	default:
		throw InternalException("Unsupported OAuth2 credentials grant type");
	}
}

static bool IsUserDelegated(const OAuth2Credentials &credentials) {
	switch (credentials.grant_type) {
	case OAuth2GrantType::REFRESH_TOKEN:
		return credentials.Cast<RefreshTokenCredentials>().user_delegated;
	case OAuth2GrantType::DEVICE_CODE:
		return true;
	default:
		return false;
	}
}

//! Adds client authentication to a form body; public clients only send their client_id.
static void AddClientAuthenticationParameters(const ClientCredentials &client, vector<string> &parameters) {
	parameters.push_back(StringUtil::Format("client_id=%s", XWWWFormUrlEncode(client.client_id)));
	if (!client.client_secret.empty()) {
		parameters.push_back(StringUtil::Format("client_secret=%s", XWWWFormUrlEncode(client.client_secret)));
	}
}

static HTTPHeaders CreateFormHeaders(ClientContext &context, const unordered_map<string, string> &extra_http_headers) {
	HTTPHeaders headers(*context.db);
	// Forward user-supplied headers (e.g. `Polaris-Realm` for multi-tenant Polaris catalogs, see
	// issue #978) before the service headers so the latter always take precedence.
	for (auto &entry : extra_http_headers) {
		headers.Insert(entry.first, entry.second);
	}
	headers.Insert("Content-Type", "application/x-www-form-urlencoded");
	return headers;
}

static unique_ptr<HTTPResponse> PostForm(ClientContext &context, const string &uri, HTTPHeaders &headers,
                                         const vector<string> &parameters) {
	auto post_data = StringUtil::Join(parameters, "&");
	try {
		auto endpoint_builder = IRCEndpointBuilder::FromURL(uri);
		return APIUtils::Request(RequestType::POST_REQUEST, context, endpoint_builder, headers, post_data);
	} catch (std::exception &ex) {
		// Only catch actual transport/network errors (not HTTP errors)
		ErrorData error(ex);
		throw InvalidConfigurationException("Could not get token from %s: %s", uri, error.RawMessage());
	}
}

static bool IsSuccess(const HTTPResponse &response) {
	return response.status >= HTTPStatusCode::OK_200 && response.status < HTTPStatusCode::MultipleChoices_300;
}

//! Describes a failed OAuth2 response; sets error_code when the body is an RFC 6749 Section 5.2 error.
static string DescribeErrorResponse(const string &uri, const HTTPResponse &response, string &error_code) {
	if (response.status >= HTTPStatusCode::BadRequest_400 &&
	    response.status < HTTPStatusCode::InternalServerError_500) {
		JSONParseError parse_error;
		auto doc = JSONDocument::TryParse(response.body.c_str(), response.body.size(), parse_error);
		if (doc) {
			auto root = doc->GetRoot();
			try {
				auto oauth_error = rest_api_objects::OAuthError::FromJSON(root);
				error_code = oauth_error._error;
				string error_msg = StringUtil::Format("OAuth2 token request failed (%s): %s",
				                                      EnumUtil::ToString(response.status), oauth_error._error);
				if (oauth_error.error_description) {
					error_msg += StringUtil::Format(" - %s", *oauth_error.error_description);
				}
				if (oauth_error.error_uri) {
					error_msg += StringUtil::Format(" (see %s)", *oauth_error.error_uri);
				}
				return error_msg;
			} catch (InvalidInputException &) {
				// Not a valid OAuth error response, fall through to generic error
			}
		}
		return StringUtil::Format("Could not get token from %s: HTTP %s - %s", uri, EnumUtil::ToString(response.status),
		                          response.body);
	}
	return StringUtil::Format("Could not get token from %s: HTTP %s - %s", uri, EnumUtil::ToString(response.status),
	                          response.reason);
}

//! Sends a token request (RFC 6749) without interpreting the response.
//! Relies on DuckDB's built-in HTTP retry infrastructure (RunRequestWithRetry) for transient errors.
static unique_ptr<HTTPResponse> SendTokenRequest(ClientContext &context, const OAuth2Credentials &credentials,
                                                 const string &uri, const string &scope) {
	vector<string> parameters;
	auto headers = CreateFormHeaders(context, credentials.extra_http_headers);

	switch (credentials.grant_type) {
	case OAuth2GrantType::CLIENT_CREDENTIALS: {
		auto &client = credentials.Cast<ClientCredentials>();
		parameters.push_back("grant_type=client_credentials");
		parameters.push_back(StringUtil::Format("scope=%s", XWWWFormUrlEncode(scope)));
		auto basic_auth = StringUtil::Format("%s:%s", client.client_id, client.client_secret);
		string_t credentials_blob(basic_auth.data(), basic_auth.size());
		headers.Insert("Authorization", StringUtil::Format("Basic %s", Blob::ToBase64(credentials_blob)));
		break;
	}
	case OAuth2GrantType::REFRESH_TOKEN: {
		auto &refresh = credentials.Cast<RefreshTokenCredentials>();
		// Google requires client authentication in the POST body for refresh-token grants.
		parameters.push_back("grant_type=refresh_token");
		parameters.push_back(StringUtil::Format("refresh_token=%s", XWWWFormUrlEncode(refresh.refresh_token)));
		AddClientAuthenticationParameters(refresh.client_credentials, parameters);
		// Omitting scope preserves the original grant's scopes.
		if (!scope.empty()) {
			parameters.push_back(StringUtil::Format("scope=%s", XWWWFormUrlEncode(scope)));
		}
		break;
	}
	case OAuth2GrantType::DEVICE_CODE: {
		// RFC 8628 Section 3.4: the scope was already bound by the device authorization request.
		auto &device = credentials.Cast<DeviceCodeCredentials>();
		parameters.push_back(StringUtil::Format("grant_type=%s", XWWWFormUrlEncode(DEVICE_CODE_GRANT_TYPE)));
		parameters.push_back(StringUtil::Format("device_code=%s", XWWWFormUrlEncode(device.device_code)));
		AddClientAuthenticationParameters(device.client_credentials, parameters);
		break;
	}
	default:
		throw InternalException("Unsupported OAuth2 credentials grant type");
	}
	return PostForm(context, uri, headers, parameters);
}

//! Parses a token response. On failure returns false with the OAuth2 error code (if any) and an error message.
static bool TryParseTokenResponse(const string &uri, const HTTPResponse &response,
                                  rest_api_objects::OAuthTokenResponse &result, string &error_code,
                                  string &error_message) {
	if (!IsSuccess(response)) {
		error_message = DescribeErrorResponse(uri, response, error_code);
		return false;
	}
	JSONParseError parse_error;
	auto doc = JSONDocument::TryParse(response.body.c_str(), response.body.size(), parse_error);
	if (!doc) {
		error_message = StringUtil::Format("Could not get token from %s: server returned invalid JSON", uri);
		return false;
	}
	auto root = doc->GetRoot();
	result = rest_api_objects::OAuthTokenResponse::FromJSON(root);
	if (!StringUtil::CIEquals(result.token_type, "bearer")) {
		throw NotImplementedException(
		    "token_type return value '%s' is not supported, only supports 'bearer' currently.", result.token_type);
	}
	return true;
}

static rest_api_objects::OAuthTokenResponse FetchOAuth2TokenResponse(ClientContext &context,
                                                                     const OAuth2Credentials &credentials,
                                                                     const string &uri, const string &scope) {
	auto response = SendTokenRequest(context, credentials, uri, scope);
	rest_api_objects::OAuthTokenResponse result;
	string error_code;
	string error_message;
	if (!TryParseTokenResponse(uri, *response, result, error_code, error_message)) {
		throw InvalidConfigurationException(error_message);
	}
	return result;
}

//! Device authorization response (RFC 8628 Section 3.2)
struct DeviceAuthorization {
	string device_code;
	string user_code;
	string verification_uri;
	string verification_uri_complete;
	int64_t expires_in = 0;
	int64_t interval = 5;
};

static string GetRequiredString(JSONValue root, const char *name, const string &uri) {
	auto value = root.GetMember(name);
	if (!value.IsValid() || !rest_api_objects::json_utils::IsString(value)) {
		throw InvalidConfigurationException("Device authorization response from %s is missing '%s'", uri, name);
	}
	return rest_api_objects::json_utils::GetString(value);
}

static DeviceAuthorization RequestDeviceAuthorization(ClientContext &context, const ClientCredentials &client,
                                                      const unordered_map<string, string> &extra_http_headers,
                                                      const string &uri, const string &scope) {
	vector<string> parameters;
	AddClientAuthenticationParameters(client, parameters);
	if (!scope.empty()) {
		parameters.push_back(StringUtil::Format("scope=%s", XWWWFormUrlEncode(scope)));
	}
	auto headers = CreateFormHeaders(context, extra_http_headers);
	auto response = PostForm(context, uri, headers, parameters);
	if (!IsSuccess(*response)) {
		string error_code;
		throw InvalidConfigurationException(DescribeErrorResponse(uri, *response, error_code));
	}
	JSONParseError parse_error;
	auto doc = JSONDocument::TryParse(response->body.c_str(), response->body.size(), parse_error);
	if (!doc) {
		throw InvalidConfigurationException("Device authorization request to %s returned invalid JSON", uri);
	}
	auto root = doc->GetRoot();
	DeviceAuthorization result;
	result.device_code = GetRequiredString(root, "device_code", uri);
	result.user_code = GetRequiredString(root, "user_code", uri);
	// Google returns the non-standard 'verification_url'.
	auto verification_url = root.GetMember("verification_url");
	if (!root.GetMember("verification_uri").IsValid() && verification_url.IsValid()) {
		result.verification_uri = GetRequiredString(root, "verification_url", uri);
	} else {
		result.verification_uri = GetRequiredString(root, "verification_uri", uri);
	}
	auto complete = root.GetMember("verification_uri_complete");
	if (complete.IsValid() && rest_api_objects::json_utils::IsString(complete)) {
		result.verification_uri_complete = rest_api_objects::json_utils::GetString(complete);
	}
	auto expires_in = root.GetMember("expires_in");
	if (!expires_in.IsValid() || !rest_api_objects::json_utils::IsInteger(expires_in)) {
		throw InvalidConfigurationException("Device authorization response from %s is missing 'expires_in'", uri);
	}
	result.expires_in = rest_api_objects::json_utils::GetSignedInteger(expires_in);
	auto interval = root.GetMember("interval");
	if (interval.IsValid() && rest_api_objects::json_utils::IsInteger(interval)) {
		result.interval = MaxValue<int64_t>(rest_api_objects::json_utils::GetSignedInteger(interval), 0);
	}
	return result;
}

static void WaitForPollInterval(ClientContext &context, int64_t interval_seconds) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(interval_seconds);
	while (true) {
		context.BlockingInterruptCheck();
		auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			return;
		}
		std::this_thread::sleep_for(
		    MinValue<std::chrono::steady_clock::duration>(deadline - now, std::chrono::milliseconds(100)));
	}
}

//! Runs the device authorization grant (RFC 8628) until the user approves, denies, or the code expires.
static rest_api_objects::OAuthTokenResponse
RunDeviceAuthorizationFlow(ClientContext &context, const ClientCredentials &client,
                           const unordered_map<string, string> &extra_http_headers, const string &device_uri,
                           const string &token_uri, const string &scope) {
	auto authorization = RequestDeviceAuthorization(context, client, extra_http_headers, device_uri, scope);
	auto message = authorization.verification_uri_complete.empty()
	                   ? StringUtil::Format("To authorize DuckDB, open %s and enter the code: %s",
	                                        authorization.verification_uri, authorization.user_code)
	                   : StringUtil::Format("To authorize DuckDB, open %s and confirm the code: %s",
	                                        authorization.verification_uri_complete, authorization.user_code);
	Printer::Print(OutputStream::STREAM_STDERR, message);
	DUCKDB_LOG(context, IcebergLogType, "%s", message);

	DeviceCodeCredentials credentials(client, authorization.device_code);
	credentials.extra_http_headers = extra_http_headers;
	auto interval = authorization.interval;
	auto expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(authorization.expires_in);
	while (true) {
		WaitForPollInterval(context, interval);
		if (std::chrono::steady_clock::now() >= expires_at) {
			throw InvalidConfigurationException(
			    "OAuth2 device authorization expired before it was approved; create the secret again to retry");
		}
		auto response = SendTokenRequest(context, credentials, token_uri, scope);
		rest_api_objects::OAuthTokenResponse result;
		string error_code;
		string error_message;
		if (TryParseTokenResponse(token_uri, *response, result, error_code, error_message)) {
			return result;
		}
		if (error_code == "authorization_pending") {
			continue;
		}
		if (error_code == "slow_down") {
			// RFC 8628 Section 3.5: increase the interval by 5 seconds for this and all subsequent requests.
			interval += 5;
			continue;
		}
		throw InvalidConfigurationException(error_message);
	}
}

} // namespace

string OAuth2Authorization::GetToken(ClientContext &context, const OAuth2Credentials &credentials, const string &uri,
                                     const string &scope) {
	auto token_response = FetchOAuth2TokenResponse(context, credentials, uri, scope);
	return token_response.access_token;
}

unique_ptr<OAuth2Authorization>
OAuth2Authorization::FromAttachOptions(AttachedDatabase &db, ClientContext &context, IcebergAttachOptions &input,
                                       optional_ptr<unordered_map<string, Value>> client_options) {
	unordered_map<string, Value> remaining_options;
	case_insensitive_map_t<Value> create_secret_options;
	string secret;

	static const unordered_set<string> recognized_create_secret_options {
	    "oauth2_scope",  "oauth2_server_uri", "oauth2_grant_type", "oauth2_device_authorization_uri",
	    "token",         "refresh_token",     "expires_in",        "client_id",
	    "client_secret", "extra_http_headers"};

	for (auto &entry : input.options) {
		auto lower_name = StringUtil::Lower(entry.first);
		if (lower_name == "secret") {
			secret = entry.second.ToString();
		} else if (recognized_create_secret_options.count(lower_name)) {
			create_secret_options.emplace(lower_name, lower_name == "expires_in"
			                                              ? entry.second.DefaultCastAs(LogicalType::INTEGER)
			                                              : entry.second);
		} else {
			remaining_options.emplace(std::move(entry));
		}
	}

	unique_ptr<SecretEntry> iceberg_secret;
	unique_ptr<BaseSecret> new_secret;

	if (create_secret_options.empty()) {
		//! Look up an ICEBERG secret
		iceberg_secret = IcebergCatalog::GetIcebergSecret(context, secret);
		if (!iceberg_secret) {
			if (!secret.empty()) {
				throw InvalidConfigurationException("No ICEBERG secret by the name of '%s' could be found", secret);
			} else {
				throw InvalidConfigurationException(
				    "AUTHORIZATION_TYPE is 'oauth2', yet no 'secret' was provided, and no client_id+client_secret were "
				    "provided. Please provide one of the listed options or change the 'authorization_type'.");
			}
		}
		auto &kv_iceberg_secret = dynamic_cast<const KeyValueSecret &>(*iceberg_secret->secret);
		auto uri_from_secret = kv_iceberg_secret.TryGetValue("uri");
		auto legacy_endpoint_from_secret = kv_iceberg_secret.TryGetValue("endpoint");
		if (!uri_from_secret.IsNull() && !legacy_endpoint_from_secret.IsNull()) {
			throw InvalidConfigurationException(
			    "ICEBERG secret '%s' contains both 'uri' and deprecated 'endpoint'; use only 'uri'",
			    iceberg_secret->secret->GetName().GetIdentifierName());
		}
		if (input.catalog_uri.empty()) {
			if (uri_from_secret.IsNull() && legacy_endpoint_from_secret.IsNull()) {
				throw InvalidConfigurationException(
				    "No 'uri' was given to attach, and no 'uri' could be retrieved from the ICEBERG secret!");
			}
			if (!legacy_endpoint_from_secret.IsNull()) {
				DUCKDB_LOG_WARNING(context, "The ICEBERG secret option 'endpoint' is deprecated; use 'uri' instead");
				uri_from_secret = legacy_endpoint_from_secret;
			}
			DUCKDB_LOG(context, IcebergLogType, "'uri' is inferred from the ICEBERG secret '%s'",
			           iceberg_secret->secret->GetName().GetIdentifierName());
			input.catalog_uri = uri_from_secret.ToString();
		}
		// Secret properties are client configuration too. Resolve them before applying
		// /config so defaults cannot replace them, and overrides can update individual
		// properties without combining SECRET with explicit OAuth2 options.
		if (client_options) {
			client_options->erase("secret");
			for (auto &entry : kv_iceberg_secret.secret_map) {
				auto option_name = StringUtil::Lower(entry.first.GetIdentifierName());
				if (option_name == "endpoint") {
					option_name = "uri";
				}
				client_options->emplace(option_name, entry.second);
			}
		}
	} else {
		if (!secret.empty()) {
			set<string> option_names;
			for (auto &entry : create_secret_options) {
				option_names.insert(entry.first);
			}
			throw InvalidConfigurationException(
			    "Both 'secret' and the following oauth2 option(s) were given: %s. These are mutually exclusive",
			    StringUtil::Join(option_names, ", "));
		}

		CreateSecretInput create_secret_input;
		if (!input.catalog_uri.empty()) {
			create_secret_options["uri"] = input.catalog_uri;
		}
		create_secret_input.options = std::move(create_secret_options);
		new_secret = OAuth2Authorization::CreateCatalogSecretFunction(context, create_secret_input);
	}

	const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(new_secret ? *new_secret : *iceberg_secret->secret);
	const auto server_uri = kv_secret.TryGetValue("oauth2_server_uri");
	const auto scope = kv_secret.TryGetValue("oauth2_scope");
	auto result = make_uniq<OAuth2Authorization>(db, ExtractOAuth2CredentialsFromSecret(kv_secret),
	                                             server_uri.IsNull() ? "" : server_uri.ToString(),
	                                             scope.IsNull() ? "" : scope.ToString());
	const auto token = kv_secret.TryGetValue("token");
	if (token.IsNull()) {
		throw HTTPException(StringUtil::Format("Failed to retrieve OAuth2 token from %s", result->uri));
	}
	{
		annotated_lock_guard<annotated_mutex> lock(result->token_mutex);
		result->token = token.ToString();

		const auto expires_in = kv_secret.TryGetValue("expires_in");
		if (!expires_in.IsNull() && expires_in.type().id() == LogicalTypeId::INTEGER &&
		    (new_secret || expires_in.GetValue<int32_t>() > 0)) {
			// Preserve the refresh credentials extracted above.
			result->UpdateTokenState(result->token, expires_in.GetValue<int32_t>(), "");
		}
	}

	IcebergAuthorization::ParseExtraHttpHeaders(kv_secret.TryGetValue("extra_http_headers"),
	                                            result->extra_http_headers);

	input.options = std::move(remaining_options);
	return result;
}

unique_ptr<BaseSecret> OAuth2Authorization::CreateCatalogSecretFunction(ClientContext &context,
                                                                        CreateSecretInput &input) {
	// apply any overridden settings
	vector<string> prefix_paths;
	auto result = make_uniq<KeyValueSecret>(prefix_paths, "iceberg", "config", input.name);
	result->redact_keys = {"token", "client_id", "client_secret", "refresh_token"};

	auto &accepted_parameters = IcebergSecretOptions();
	bool uri_option_set = false;
	bool legacy_endpoint_option_set = false;
	for (const auto &named_param : input.options) {
		auto lower_name = StringUtil::Lower(named_param.first);
		uri_option_set |= lower_name == "uri";
		legacy_endpoint_option_set |= lower_name == "endpoint";
	}
	if (uri_option_set && legacy_endpoint_option_set) {
		throw InvalidConfigurationException(
		    "Both 'uri' and deprecated 'endpoint' were provided for an ICEBERG secret; use only 'uri'");
	}
	if (legacy_endpoint_option_set) {
		DUCKDB_LOG_WARNING(context, "The ICEBERG secret option 'endpoint' is deprecated; use 'uri' instead");
	}

	for (const auto &named_param : input.options) {
		auto &param_name = named_param.first;
		auto it = accepted_parameters.find(param_name);
		if (it != accepted_parameters.end()) {
			auto normalized_param_name = StringUtil::Lower(param_name) == "endpoint" ? "uri" : param_name;
			// Special handling for extra_http_headers (MAP type)
			if (StringUtil::Lower(param_name) == "extra_http_headers") {
				// Store the MAP value directly, will be parsed later when creating authorization
				result->secret_map[Identifier(normalized_param_name)] = named_param.second;
			} else if (StringUtil::Lower(param_name) == "expires_in") {
				// Store expires_in as INTEGER (not string)
				result->secret_map[Identifier(normalized_param_name)] = named_param.second;
			} else {
				auto value = named_param.second.ToString();
				if (normalized_param_name == "uri") {
					StringUtil::RTrim(value, "/");
				}
				result->secret_map[Identifier(normalized_param_name)] = std::move(value);
			}
		} else {
			throw InvalidInputException("Unknown named parameter passed to CreateIRCSecretFunction: %s", param_name);
		}
	}

	//! ---- Token ----
	auto token_it = result->secret_map.find("token");
	if (token_it != result->secret_map.end()) {
		return std::move(result);
	}

	//! ---- OAuth2 Server URI (with deprecated catalog-relative fallback) ----
	string server_uri;
	auto oauth2_server_uri_it = result->secret_map.find("oauth2_server_uri");
	auto catalog_uri_it = result->secret_map.find("uri");
	if (oauth2_server_uri_it != result->secret_map.end()) {
		server_uri = oauth2_server_uri_it->second.ToString();
	} else if (catalog_uri_it != result->secret_map.end()) {
		DUCKDB_LOG(
		    context, IcebergLogType,
		    "'oauth2_server_uri' is not set, defaulting to deprecated '{uri}/v1/oauth/tokens' oauth2_server_uri");
		server_uri = StringUtil::Format("%s/v1/oauth/tokens", catalog_uri_it->second.ToString());
	} else {
		throw InvalidConfigurationException(
		    "AUTHORIZATION_TYPE is 'oauth2', yet no 'oauth2_server_uri' was provided, and no 'uri' was provided "
		    "to fall back on. Please provide one or change the 'authorization_type'.");
	}

	auto grant_type_it = result->secret_map.find("oauth2_grant_type");
	const bool device_code =
	    grant_type_it != result->secret_map.end() && IsDeviceCodeGrant(grant_type_it->second.ToString());
	if (device_code) {
		result->secret_map["oauth2_grant_type"] = "device_code";
	}

	//! ---- Client ID + Client Secret ----
	// Device-code clients may be public clients, which have no secret.
	case_insensitive_set_t required_parameters {"client_id"};
	if (!device_code) {
		required_parameters.insert("client_secret");
	}
	for (auto &param : required_parameters) {
		if (!result->secret_map.count(Identifier(param))) {
			throw InvalidInputException("Missing required parameter '%s' for authorization_type 'oauth2'", param);
		}
	}

	//! ---- Grant Type and Token Acquisition ----
	// Determine which grant type to use for initial token acquisition
	string scope_to_use;

	// Check if refresh_token was provided
	auto refresh_token_it = result->secret_map.find("refresh_token");
	if (refresh_token_it != result->secret_map.end()) {
		// User provided a refresh_token - use refresh_token grant
		// Don't send scope in refresh_token grant (use original token scopes)
		// Per RFC 6749 Section 6, scope is optional and if omitted, is treated as equal to original scope
		auto scope_it = result->secret_map.find("oauth2_scope");
		scope_to_use = (scope_it != result->secret_map.end()) ? scope_it->second.ToString() : "";
	} else if (device_code) {
		auto scope_it = result->secret_map.find("oauth2_scope");
		scope_to_use = (scope_it != result->secret_map.end()) ? scope_it->second.ToString() : "";
	} else {
		// No refresh_token - use client_credentials grant
		if (grant_type_it != result->secret_map.end()) {
			auto grant_type_to_use = grant_type_it->second.ToString();
			if (!StringUtil::CIEquals(grant_type_to_use, "client_credentials")) {
				throw InvalidInputException("Unsupported option ('%s') for 'oauth2_grant_type', only supports "
				                            "'client_credentials' and 'device_code' currently",
				                            grant_type_to_use);
			}
		}
		// Default scope for client_credentials grant
		if (!result->secret_map.count("oauth2_scope")) {
			result->secret_map["oauth2_scope"] = "PRINCIPAL_ROLE:ALL";
		}
		scope_to_use = result->secret_map["oauth2_scope"].ToString();
	}

	// Make a request to the oauth2 server uri to get the (bearer) token
	// Store the full response to capture expires_in and refresh_token
	rest_api_objects::OAuthTokenResponse token_response;
	if (device_code && refresh_token_it == result->secret_map.end()) {
		auto device_uri_it = result->secret_map.find("oauth2_device_authorization_uri");
		if (device_uri_it == result->secret_map.end()) {
			throw InvalidInputException(
			    "Missing required parameter 'oauth2_device_authorization_uri' for oauth2_grant_type 'device_code'");
		}
		auto client_secret_it = result->secret_map.find("client_secret");
		ClientCredentials client(result->secret_map["client_id"].ToString(),
		                         client_secret_it == result->secret_map.end() ? string()
		                                                                      : client_secret_it->second.ToString());
		unordered_map<string, string> extra_http_headers;
		IcebergAuthorization::ParseExtraHttpHeaders(result->TryGetValue("extra_http_headers"), extra_http_headers);
		token_response = RunDeviceAuthorizationFlow(context, client, extra_http_headers,
		                                            device_uri_it->second.ToString(), server_uri, scope_to_use);
		if (!token_response.refresh_token || token_response.refresh_token->empty()) {
			auto scopes = StringUtil::Split(scope_to_use, ' ');
			auto requested_offline_access = std::find(scopes.begin(), scopes.end(), "offline_access") != scopes.end();
			DUCKDB_LOG_WARNING(
			    context,
			    "The OAuth2 server issued no refresh token, so the token cannot be renewed once it "
			    "expires and the secret must then be created again%s",
			    requested_offline_access ? "" : "; if the server requires it, add 'offline_access' to OAUTH2_SCOPE");
		}
	} else {
		auto credentials = ExtractOAuth2CredentialsFromSecret(*result);
		token_response = FetchOAuth2TokenResponse(context, *credentials, server_uri, scope_to_use);
	}

	result->secret_map["token"] = token_response.access_token;

	// Store refresh_token if present (RFC 6749 Section 6)
	if (token_response.refresh_token && !token_response.refresh_token->empty()) {
		result->secret_map["refresh_token"] = *token_response.refresh_token;
	}

	// Store expires_in if present
	if (token_response.expires_in) {
		result->secret_map["expires_in"] = Value::INTEGER(*token_response.expires_in);
	}

	// Store the credentials for later refresh (already in secret_map)
	// We keep client_id, client_secret, oauth2_server_uri, oauth2_scope for refresh

	return std::move(result);
}

unique_ptr<HTTPResponse> OAuth2Authorization::Request(RequestType request_type, ClientContext &context,
                                                      const IRCEndpointBuilder &endpoint_builder, HTTPHeaders &headers,
                                                      const string &data) {
	// --- Step 1: Proactive refresh under lock, then copy token ---
	// Serialized refresh: at most one thread refreshes at a time.
	// Refresh I/O under lock is acceptable (rare, bounded by token lifetime).
	// Threads that queue behind the mutex will re-check expiry, see the
	// fresh token, and skip refresh.
	string bearer_token;
	{
		annotated_lock_guard<annotated_mutex> lock(token_mutex);
		if (IsTokenExpiredUnlocked(context) && CanRefreshUnlocked()) {
			RefreshAccessTokenUnlocked(context);
		}
		bearer_token = token;
	}
	// Lock released -- catalog HTTP request runs concurrently with other threads.

	// --- Step 2: Build headers and make the catalog request ---
	for (auto &entry : extra_http_headers) {
		headers.Insert(entry.first, entry.second);
	}
	if (!bearer_token.empty()) {
		headers["Authorization"] = StringUtil::Format("Bearer %s", bearer_token);
	}

	auto response = APIUtils::Request(request_type, context, endpoint_builder, headers, data);

	// --- Step 3: Reactive 401 refresh (exactly once) ---
	// If the server rejected our token (e.g., revoked before expiry, clock skew,
	// audience change), refresh once and retry. Guard against infinite loops.
	if (response->status == HTTPStatusCode::Unauthorized_401) {
		bool should_retry = false;
		{
			annotated_lock_guard<annotated_mutex> lock(token_mutex);
			if (CanRefreshUnlocked()) {
				RefreshAccessTokenUnlocked(context);
				bearer_token = token;
				should_retry = true;
			}
		}
		// Lock released before retry -- avoid serializing catalog requests
		if (should_retry) {
			headers["Authorization"] = StringUtil::Format("Bearer %s", bearer_token);
			response = APIUtils::Request(request_type, context, endpoint_builder, headers, data);
		}
	}

	return response;
}

void OAuth2Authorization::SetCatalogSecretParameters(CreateSecretFunction &function) {
	auto &options = IcebergSecretOptions();
	for (auto &option : options) {
		function.named_parameters[Identifier(option.first)] = option.second;
	}
}

void OAuth2Authorization::UpdateTokenState(const string &new_token, int32_t expires_in_seconds,
                                           const string &new_refresh_token) {
	token = new_token;

	// Only update refresh_token if a new one is provided (RFC 6749 Section 6)
	// "The authorization server MAY issue a new refresh token, in which case
	// the client MUST discard the old refresh token and replace it with the new one."
	// If no new refresh_token is provided, keep the existing one.
	//
	// NOTE: Rotation is in-memory only. The original secret in SecretManager is NOT updated.
	// After DETACH + re-ATTACH, the rotated refresh_token is lost and the client falls back
	// to client_credentials if available. This is a known limitation.
	if (!new_refresh_token.empty()) {
		D_ASSERT(credentials);
		credentials = make_uniq<RefreshTokenCredentials>(GetClientCredentials(*credentials), new_refresh_token,
		                                                 IsUserDelegated(*credentials));
	}

	// Determine which expires_in to use
	int32_t effective_expires_in = expires_in_seconds;
	if (expires_in_seconds <= 0) {
		// Server omitted expires_in: reuse previous value if available, else use conservative default
		if (last_expires_in > 0) {
			effective_expires_in = last_expires_in;
		} else {
			// No previous expiry known: apply conservative default (1 hour)
			effective_expires_in = 3600;
		}
	} else {
		// Store the new expires_in for future reuse
		last_expires_in = expires_in_seconds;
	}

	if (effective_expires_in > 0) {
		// Calculate expiry time with safety buffer (clamped to avoid negative durations)
		auto now = std::chrono::system_clock::now();
		auto buffer_seconds =
		    std::min(30, effective_expires_in / 2); // Use 30s or half the lifetime, whichever is smaller
		auto expiry_duration = std::chrono::seconds(effective_expires_in - buffer_seconds);
		auto expiry_time = now + expiry_duration;
		token_expires_at = std::chrono::duration_cast<std::chrono::seconds>(expiry_time.time_since_epoch()).count();
	} else {
		// No expiry information available at all (shouldn't happen with the logic above)
		token_expires_at = 0;
	}
}

bool OAuth2Authorization::IsTokenExpiredUnlocked(ClientContext &context) const {
	// Test hook to force token expiry (for test infrastructure)
	Value force_expiry_val;
	if (context.TryGetCurrentSetting("iceberg_test_force_token_expiry", force_expiry_val)) {
		if (!force_expiry_val.IsNull() && force_expiry_val.type().id() == LogicalTypeId::BOOLEAN &&
		    force_expiry_val.GetValue<bool>()) {
			return true;
		}
	}

	// Check normal expiry
	if (token_expires_at == 0) {
		// No expiry set = token never expires (static token or no expires_in in response)
		return false;
	}

	auto now = std::chrono::system_clock::now();
	auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
	return now_seconds >= token_expires_at;
}

bool OAuth2Authorization::CanRefreshUnlocked() const {
	// Token-only configurations have no credentials with which to acquire a new token.
	return credentials && !uri.empty();
}

void OAuth2Authorization::RefreshAccessTokenUnlocked(ClientContext &context) {
	if (!CanRefreshUnlocked()) {
		throw HTTPException("Cannot refresh access token: no refresh_token and no client credentials available");
	}

	rest_api_objects::OAuthTokenResponse token_response;
	if (IsUserDelegated(*credentials)) {
		try {
			token_response = FetchOAuth2TokenResponse(context, *credentials, uri, scope);
		} catch (std::exception &ex) {
			ErrorData error(ex);
			throw InvalidConfigurationException(
			    "Could not refresh the OAuth2 token; create the secret again to re-authorize: %s", error.RawMessage());
		}
	} else if (credentials->grant_type == OAuth2GrantType::REFRESH_TOKEN) {
		try {
			token_response = FetchOAuth2TokenResponse(context, *credentials, uri, scope);
		} catch (std::exception &) {
			// A failed refresh-token grant can fall back to client credentials.
			const auto &client = GetClientCredentials(*credentials);
			credentials = make_uniq<ClientCredentials>(client.client_id, client.client_secret);
			token_response = FetchOAuth2TokenResponse(context, *credentials, uri, scope);
		}
	} else {
		token_response = FetchOAuth2TokenResponse(context, *credentials, uri, scope);
	}

	// Update our token state with the new token (UpdateTokenState assumes lock is held)
	UpdateTokenState(token_response.access_token, token_response.expires_in.value_or(0),
	                 token_response.refresh_token.value_or(""));
}

} // namespace duckdb
