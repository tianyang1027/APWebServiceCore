namespace Microsoft.Bing.Multimedia.APWebServiceCore
{
    using System;
    using System.Net;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    public class ServiceStartup
    {
        public ServiceStartup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
               .SetBasePath(env.ContentRootPath)
               .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
               .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; set; }

        public virtual void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(o =>
            {
                o.MetadataAddress = Configuration["aad:MetadataAddress"];
                o.ClientId = Configuration["aad:oidc:ClientId"];
                o.SignedOutRedirectUri = Configuration["aad:oidc:PostLogoutRedirectUri"];

                o.Events = new OpenIdConnectEvents
                {
                    OnRemoteFailure = OnAuthenticationFailed
                };
            })
            .AddJwtBearer(o =>
            {
                o.MetadataAddress = Configuration["aad:MetadataAddress"];
                o.Audience = Configuration["aad:jwt:Audience"];
            });

            services.AddMvc();

            ConfigureAdditionalServices(services);
        }

        public virtual void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            app.UseAuthentication();

            app.Use(async (ctx, next) => await HandleKeepaliveRequests(ctx, next));
            app.Use(async (ctx, next) => await HandleUserSessionRequests(ctx, next));

            loggerFactory.AddConsole();
        }

        protected virtual void ConfigureAdditionalServices(IServiceCollection services)
        {
        }

        private async Task HandleKeepaliveRequests(HttpContext ctx, Func<Task> next)
        {
            var path = ctx.Request.Path;
            if (path.StartsWithSegments("/keepalive") || path.StartsWithSegments("//keepalive"))
                ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            else
                await next();
        }

        private async Task HandleUserSessionRequests(HttpContext ctx, Func<Task> next)
        {
            var path = ctx.Request.Path;

            if (path.StartsWithSegments("/login"))
            {
                if (ctx.User == null || !ctx.User.Identity.IsAuthenticated)
                    await ctx.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/" });
            }
            else if (path.StartsWithSegments("/logout"))
            {
                if (ctx.User.Identity.IsAuthenticated)
                {
                    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            else if (path.StartsWithSegments("/endsession"))
            {
                await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
            else
            {
                await next();
            }
        }

        private Task OnAuthenticationFailed(RemoteFailureContext ctx)
        {
            ctx.HandleResponse();
            ctx.Response.Redirect("/error?message=" + ctx.Failure.Message);

            return Task.FromResult(0);
        }
    }
}