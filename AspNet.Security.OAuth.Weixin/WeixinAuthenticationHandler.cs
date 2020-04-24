/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OAuth.Weixin
{
    public class WeixinAuthenticationHandler : OAuthHandler<WeixinAuthenticationOptions>
    {
        public WeixinAuthenticationHandler(
            [NotNull] IOptionsMonitor<WeixinAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        private const string OauthState = "_oauthstate";
        private const string State = "state";

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            if (!IsWeixinAuthorizationEndpointInUse())
            {
                if (Request.Query.TryGetValue(OauthState, out var stateValue))
                {
                    var queryWeiXin = Request.Query.ToDictionary(c => c.Key, c => c.Value, StringComparer.OrdinalIgnoreCase);
                    if (queryWeiXin.TryGetValue(State, out var _))
                    {
                        queryWeiXin[State] = stateValue;
                        Request.QueryString = QueryString.Create(queryWeiXin);
                    }
                }
            }

            return await base.HandleRemoteAuthenticateAsync();

            //var query = Request.Query;

            //var state = query["state"];
            //var properties = Options.StateDataFormat.Unprotect(state);

            //if (properties == null)
            //{
            //    return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            //}

            //// OAuth2 10.12 CSRF 这里去掉了csrf验证,有的手机无法通过验证,不知道为什么
            ////if (ValidateCorrelationId(properties))
            ////{
            ////    return HandleRequestResult.Fail("Correlation failed.", properties);
            ////}

            //var error = query["error"];
            //if (!StringValues.IsNullOrEmpty(error))
            //{
            //    // Note: access_denied errors are special protocol errors indicating the user didn't
            //    // approve the authorization demand requested by the remote authorization server.
            //    // Since it's a frequent scenario (that is not caused by incorrect configuration),
            //    // denied errors are handled differently using HandleAccessDeniedErrorAsync().
            //    // Visit https://tools.ietf.org/html/rfc6749#section-4.1.2.1 for more information.
            //    var errorDescription = query["error_description"];
            //    var errorUri = query["error_uri"];
            //    if (StringValues.Equals(error, "access_denied"))
            //    {
            //        var result = await HandleAccessDeniedErrorAsync(properties);
            //        if (!result.None)
            //        {
            //            return result;
            //        }
            //        var deniedEx = new Exception("Access was denied by the resource owner or by the remote server.");
            //        deniedEx.Data["error"] = error.ToString();
            //        deniedEx.Data["error_description"] = errorDescription.ToString();
            //        deniedEx.Data["error_uri"] = errorUri.ToString();

            //        return HandleRequestResult.Fail(deniedEx, properties);
            //    }

            //    var failureMessage = new StringBuilder();
            //    failureMessage.Append(error);
            //    if (!StringValues.IsNullOrEmpty(errorDescription))
            //    {
            //        failureMessage.Append(";Description=").Append(errorDescription);
            //    }
            //    if (!StringValues.IsNullOrEmpty(errorUri))
            //    {
            //        failureMessage.Append(";Uri=").Append(errorUri);
            //    }

            //    var ex = new Exception(failureMessage.ToString());
            //    ex.Data["error"] = error.ToString();
            //    ex.Data["error_description"] = errorDescription.ToString();
            //    ex.Data["error_uri"] = errorUri.ToString();

            //    return HandleRequestResult.Fail(ex, properties);
            //}

            //var code = query["code"];

            //if (StringValues.IsNullOrEmpty(code))
            //{
            //    return HandleRequestResult.Fail("Code was not found.", properties);
            //}

            //var codeExchangeContext = new OAuthCodeExchangeContext(properties, code, BuildRedirectUri(Options.CallbackPath));
            //using var tokens = await ExchangeCodeAsync(codeExchangeContext);

            //if (tokens.Error != null)
            //{
            //    return HandleRequestResult.Fail(tokens.Error, properties);
            //}

            //if (string.IsNullOrEmpty(tokens.AccessToken))
            //{
            //    return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            //}

            //var identity = new ClaimsIdentity(ClaimsIssuer);

            //if (Options.SaveTokens)
            //{
            //    var authTokens = new List<AuthenticationToken>();

            //    authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
            //    if (!string.IsNullOrEmpty(tokens.RefreshToken))
            //    {
            //        authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
            //    }

            //    if (!string.IsNullOrEmpty(tokens.TokenType))
            //    {
            //        authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
            //    }

            //    if (!string.IsNullOrEmpty(tokens.ExpiresIn))
            //    {
            //        int value;
            //        if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            //        {
            //            // https://www.w3.org/TR/xmlschema-2/#dateTime
            //            // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
            //            var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
            //            authTokens.Add(new AuthenticationToken
            //            {
            //                Name = "expires_at",
            //                Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
            //            });
            //        }
            //    }

            //    properties.StoreTokens(authTokens);
            //}

            //var ticket = await CreateTicketAsync(identity, properties, tokens);
            //if (ticket != null)
            //{
            //    return HandleRequestResult.Success(ticket);
            //}
            //else
            //{
            //    return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
            //}
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties,
            [NotNull] OAuthTokenResponse tokens)
        {
            string address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
                ["openid"] = tokens.Response.RootElement.GetString("openid")
            });

            using var response = await Backchannel.GetAsync(address);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!string.IsNullOrEmpty(payload.RootElement.GetString("errcode")))
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
            context.RunClaimActions();

            await Options.Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync([NotNull] OAuthCodeExchangeContext context)
        {
            string address = QueryHelpers.AddQueryString(Options.TokenEndpoint, new Dictionary<string, string>()
            {
                ["appid"] = Options.ClientId,
                ["secret"] = Options.ClientSecret,
                ["code"] = context.Code,
                ["grant_type"] = "authorization_code"
            });

            using var response = await Backchannel.GetAsync(address);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }

            var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!string.IsNullOrEmpty(payload.RootElement.GetString("errcode")))
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }

            return OAuthTokenResponse.Success(payload);
        }

        protected override string BuildChallengeUrl([NotNull] AuthenticationProperties properties, [NotNull] string redirectUri)
        {
            string stateValue = Options.StateDataFormat.Protect(properties);
            bool addRedirectHash = false;

            if (!IsWeixinAuthorizationEndpointInUse())
            {
                // Store state in redirectUri when authorizing Wechat Web pages to prevent "too long state parameters" error
                redirectUri = QueryHelpers.AddQueryString(redirectUri, OauthState, stateValue);
                addRedirectHash = true;
            }

            redirectUri = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
            {
                ["appid"] = Options.ClientId,
                ["scope"] = FormatScope(),
                ["response_type"] = "code",
                ["redirect_uri"] = redirectUri,
                [State] = addRedirectHash ? OauthState : stateValue
            });

            if (addRedirectHash)
            {
                // The parameters necessary for Web Authorization of Wechat
                redirectUri += "#wechat_redirect";
            }

            return redirectUri;
        }

        protected override string FormatScope() => string.Join(",", Options.Scope);

        private bool IsWeixinAuthorizationEndpointInUse()
        {
            return string.Equals(Options.AuthorizationEndpoint, WeixinAuthenticationDefaults.AuthorizationEndpoint, StringComparison.OrdinalIgnoreCase);
        }
    }
}
