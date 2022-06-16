﻿using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;

namespace BlazorOreoreAuth.Auth;

public class CustomSessionStorageAuthenticationStateProvider : AuthenticationStateProvider
{
    private static readonly AuthenticationState UnauthorizedAuthenticationState = new AuthenticationState(new ClaimsPrincipal());
    private ClaimsPrincipal? _principal;
    private readonly ProtectedSessionStorage _protectedSessionStorage;

    public CustomSessionStorageAuthenticationStateProvider(ProtectedSessionStorage protectedSessionStorage)
    {
        _protectedSessionStorage = protectedSessionStorage;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (_principal is null) return Task.FromResult(UnauthorizedAuthenticationState);
        return Task.FromResult(new AuthenticationState(_principal));
    }

    public async Task LoadAuthenticationStateAsync()
    {
        var result = await _protectedSessionStorage.GetAsync<string>("authkey");
        if (result.Success)
        {
            var name = result.Value!;
            await UpdateSignInStatusAsync(new ClaimsPrincipal(
                new ClaimsIdentity(
                    new Claim[]
                    {
                        new(ClaimTypes.Name, name)
                    },
                    "Blazor"
                )
            ));
        }
    }

    public async Task UpdateSignInStatusAsync(ClaimsPrincipal? principal)
    {
        _principal = principal;
        if (_principal?.Identity?.IsAuthenticated ?? false)
        {
            await _protectedSessionStorage.SetAsync("authkey", _principal.Identity.Name!); // Name あるでしょ多分
        }
        else
        {
            await _protectedSessionStorage.DeleteAsync("authkey");
        }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }
}
