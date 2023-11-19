using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.Stores.Default;
using Google.Cloud.RecaptchaEnterprise.V1;
using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.DataProtection;
using GotSharp.IdSrv.Host.Health;
using GotSharp.IdSrv.Host.Internal;
using GotSharp.IdSrv.Host.Internal.IdentityExpress;
using GotSharp.IdSrv.Host.Internal.KeyVault;
using GotSharp.IdSrv.Host.Recaptcha;
using GotSharp.IdSrv.Host.Services;
using GotSharp.IdSrv.Host.Services.AzureAD;
using GotSharp.IdSrv.Host.Services.Contracts;
using IdentityExpress.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.FeatureManagement;
using Microsoft.FeatureManagement.Mvc;
using Microsoft.Graph;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;
using SendGrid.Extensions.DependencyInjection;
using Serilog;

namespace GotSharp.IdSrv.Host;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddFeatureManagement();

        var appConfigConnectionString = builder.Configuration.GetConnectionString("AppConfig");
        if (!string.IsNullOrEmpty(appConfigConnectionString))
        {
            builder.Configuration.AddAzureAppConfiguration(appConfigConnectionString);
        }

        builder.Services.AddTransient<IDisabledFeaturesHandler, RedirectDisabledFeaturesHandler>();

        // Add the generic health checks
        var telemetryConnectionString = Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING");

        builder.Services.AddHealthChecks()
            .AddCheck(HealthChecks.Initialized, () => HealthCheckResult.Healthy("Initialization done."))
            .AddDbContextCheck<IdentityExpressDbContext>(HealthChecks.IdentityDb, failureStatus: HealthStatus.Unhealthy)
            .AddDbContextCheck<ConfigurationDbContext>(HealthChecks.ConfigDb, failureStatus: HealthStatus.Unhealthy)
            .AddApplicationInsightsPublisher(
                telemetryConnectionString,
                builder.Configuration.GetValue<bool>("HealthChecks:DetailedReports"),
                builder.Configuration.GetValue<bool>("HealthChecks:ExcludeHealthyReports"),
                x =>
                {
                    x.Delay = builder.Configuration.GetValue("HealthChecks:Delay", x.Delay);
                    x.Period = builder.Configuration.GetValue("HealthChecks:Period", x.Period);
                    x.Timeout = builder.Configuration.GetValue("HealthChecks:Timeout", x.Timeout);
                });

        builder.Services.AddApplicationInsightsTelemetry();

        var mvcBuilder = builder.Services
            .AddControllersWithViews()
            .AddNewtonsoftJson(x =>
                x.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver())
            .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
            .AddSessionStateTempDataProvider();

        if (builder.Environment.IsDevelopment())
        {
            mvcBuilder.AddRazorRuntimeCompilation();
        }

        builder.Services.AddSession(x =>
        {
            x.Cookie.HttpOnly = true;
            x.Cookie.IsEssential = true;
            x.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            x.Cookie.SameSite = SameSiteMode.Lax; // Lax is needed to work between redirects, even on the same domain!
            x.Cookie.Name = builder.Configuration["CookieNames:Session"] ?? ".Session.";
        });

        builder.Services
            .AddCoreServices(builder.Configuration)
            .AddIdentityServices(builder.Configuration)
            .AddContentSecurityPolicy(builder.Configuration);

        var migrationsAssembly = typeof(Program).Assembly.FullName;
        var identityProviderConfigDb = builder.Configuration.GetConnectionString("IdentityProviderConfigDb");

        var identityServerBuilder = builder.Services
            .AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                options.UserInteraction.LoginUrl = "/login/identifier";
                options.UserInteraction.LogoutUrl = "/logout";
                options.UserInteraction.ConsentUrl = "/consent";

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;

                var licenseKey = builder.Configuration["Duende:LicenseKey"];
                if (!string.IsNullOrWhiteSpace(licenseKey))
                {
                    options.LicenseKey = licenseKey;
                }
            })
            // this adds the config data from DB (clients, resources, CORS)
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseSqlServer(identityProviderConfigDb, o =>
                    {
                        o.EnableRetryOnFailure();
                        o.MigrationsAssembly(migrationsAssembly);
                    });
            })
            .AddConfigurationStoreCache()
            // this adds the operational data from DB (codes, tokens, consents)
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseSqlServer(identityProviderConfigDb, o =>
                    {
                        o.EnableRetryOnFailure();
                        o.MigrationsAssembly(migrationsAssembly);
                    });

                // this enables automatic token cleanup. this is optional.
                options.EnableTokenCleanup = true;
            })
            .AddAspNetIdentity<IdentityExpressUser>()
            .AddAuthorizeInteractionResponseGenerator<ExtendedAuthorizeInteractionResponseGenerator>()
            .AddProfileService<CustomProfileService<IdentityExpressUser>>()
            .AddKeyManagement()
            .AddServerSideSessions();

        var applicationCookieName = builder.Configuration["CookieNames:IdentityApplication"];
        if (!string.IsNullOrEmpty(applicationCookieName))
        {
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.Name = applicationCookieName;
            });
        }

        var externalCookieName = builder.Configuration["CookieNames:IdentityExternal"];
        if (!string.IsNullOrEmpty(externalCookieName))
        {
            builder.Services.ConfigureExternalCookie(options =>
            {
                options.Cookie.Name = externalCookieName;
            });
        }

        builder.Services
            .AddAuthentication()
            .AddAzureAD(builder.Configuration);

        if (builder.Configuration.GetSection("AzureAD").Exists() && builder.Configuration.GetSection("MicrosoftGraph").Exists())
        {
            builder.Services.AddScoped<IAzureAdService, AzureAdService>();
            builder.Services.AddScoped(_ =>
            {
                var tenantId = builder.Configuration["AzureAD:TenantId"];
                var clientId = builder.Configuration["AzureAD:ClientId"];
                var clientSecret = builder.Configuration["AzureAD:ClientSecret"];
                var scopes = builder.Configuration["MicrosoftGraph:Scopes"]
                    .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .ToArray();

                return new GraphServiceClient(
                    new ClientSecretCredential(tenantId, clientId, clientSecret),
                    scopes);
            });

            // If the Microsoft Graph health check fails, show as degraded because this merely prevents some functionality from working,
            // and that functionality will then just not be available for end-users while not impacting normal usage of the SSO platform.
            builder.Services.AddHealthChecks()
                .AddCheck<AzureAdServiceHealthCheck>(HealthChecks.MicrosoftGraph, HealthStatus.Degraded);
        }
        else
        {
            builder.Services.AddScoped<IAzureAdService, NullAzureAdService>();
        }

        builder.Services.AddScoped<ImpersonationService>();
        builder.Services.Configure<ImpersonationOptions>(x =>
        {
            var section = builder.Configuration.GetSection("Impersonation");
            if (section.Exists())
            {
                x.Groups = section["Groups"]
                    .Split(new[] { ' ', ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .ToList();
            }
        });

        builder.Services.ConfigureDistributedCache(builder.Configuration, identityServerBuilder);
        builder.Services.ConfigureDataProtection(builder.Configuration, builder.Environment);

        builder.Services.AddAntiforgery(x =>
        {
            // These are the default values, added for visibility
            x.Cookie.HttpOnly = true;
            x.Cookie.IsEssential = true;
            x.Cookie.SameSite = SameSiteMode.Strict;

            // Defaults to None...
            x.Cookie.SecurePolicy = CookieSecurePolicy.Always;

            // Change the cookie name (fingerprinting)
            x.Cookie.Name = builder.Configuration["CookieNames:Xsrf"];
        });

        builder.Services.AddHsts(x =>
        {
            x.IncludeSubDomains = true;
            x.Preload = false;
            x.MaxAge = TimeSpan.FromDays(365);
        });

        builder.Services.AddRecaptcha(x => builder.Configuration.GetSection("Recaptcha").Bind(x));

        return builder.Build();
    }

    private static IServiceCollection AddCoreServices(this IServiceCollection services, IConfiguration configuration) 
    {
        services.Configure<GeneralOptions>(x => configuration.GetSection("Options").Bind(x));
        services.Configure<SendGridOptions>(x => configuration.GetSection("SendGrid").Bind(x));

        services.AddSendGrid((sp, x) =>
        {
            using var scope = sp.CreateScope();
            var options = scope.ServiceProvider.GetRequiredService<IOptionsSnapshot<SendGridOptions>>().Value;
            x.ApiKey = options.ApiKey;
        });

        services.AddHealthChecks()
            .AddCheck<SendGridHealthCheck>(HealthChecks.SendGrid, HealthStatus.Degraded);

        services
            .AddTransient<EmailSender>()
            .AddTransient<ForgotPasswordService>()
            .AddTransient<UserActivationService>()
            .AddTransient<ICallbackUrlGenerator, DefaultCallbackUrlGenerator>();

        return services;
    }

    private static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<IdentityExpressDbContext>(x => x.UseSqlServer(configuration.GetConnectionString("IdentityProviderUserDb"), o => o.EnableRetryOnFailure()));
        services.AddScoped<IdentityExpressDbContext<IdentityExpressUser>>(x => x.GetService<IdentityExpressDbContext>());

        services.AddIdentity<IdentityExpressUser, IdentityExpressRole>(x =>
            {
                x.Password.RequireDigit = true;
                x.Password.RequireLowercase = true;
                x.Password.RequireUppercase = true;
                x.Password.RequireNonAlphanumeric = true;
                x.Password.RequiredLength = 8;
                x.Password.RequiredUniqueChars = 1;

                x.SignIn.RequireConfirmedEmail = true;

                x.User.RequireUniqueEmail = true;
            })
            .AddUserManager<Services.UserManager<IdentityExpressUser>>()
            .AddUserStore<AutoSavingIdentityExpressUserStore>()
            .AddRoleStore<AutoSavingIdentityExpressRoleStore>()
            .AddIdentityExpressUserClaimsPrincipalFactory()
            .AddDefaultTokenProviders()
            .AddSignInManager<Services.SignInManager<IdentityExpressUser>>();

        services.Configure<HomeRealmDiscovery>(configuration.GetSection("HomeRealmDiscovery"));
        services.AddTransient<HomeRealmDiscoveryService>();

        return services;
    }

    private static AuthenticationBuilder AddAzureAD(this AuthenticationBuilder authenticationBuilder, IConfiguration configuration)
    {
        if (!configuration.GetSection(nameof(AuthProviders.AzureAD)).Exists())
        {
            return authenticationBuilder;
        }

        return authenticationBuilder
            .AddOpenIdConnect(AuthProviders.AzureAD, configuration["AzureAD:DisplayName"], options => 
            {
                configuration.GetSection(nameof(AuthProviders.AzureAD)).Bind(options);

                var correlationCookieName = configuration["CookieNames:CorrelationAzureAD"];
                if (!string.IsNullOrEmpty(correlationCookieName))
                {
                    options.CorrelationCookie.Name = correlationCookieName;
                }

                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.GetClaimsFromUserInfoEndpoint = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        if (context.Properties.Items.ContainsKey("scheme") &&
                            context.Properties.Items["scheme"] == AuthProviders.AzureAD)
                        {
                            if (context.Properties.Items.ContainsKey("prompt"))
                            {
                                // set prompt value for Microsoft login
                                context.ProtocolMessage.SetParameter("prompt",
                                    context.Properties.Items["prompt"]);
                            }

                            if (context.Properties.Parameters.ContainsKey("login_hint"))
                            {
                                // set login_hint
                                context.ProtocolMessage.LoginHint =
                                    context.Properties.GetParameter<string>("login_hint");
                            }

                            // set domain_hint
                            context.ProtocolMessage.DomainHint = configuration["AzureAD:DomainHint"] ?? "";
                        }

                        return Task.CompletedTask;
                    }
                };
            }
        );
    }

    private static void ConfigureDistributedCache(this IServiceCollection services, IConfiguration configuration, IIdentityServerBuilder identityServerBuilder)
    {
        var cacheType = configuration["DistributedCache:ServiceType"];
        switch (cacheType?.ToLowerInvariant())
        {
            case "sqlserver":
                services.AddDistributedSqlServerCache(x =>
                {
                    configuration.GetSection("DistributedCache:SqlServer").Bind(x);
                });

                identityServerBuilder.AddAuthorizationParametersMessageStore<DistributedCacheAuthorizationParametersMessageStore>();
                break;
            default:
                // Development or single-instance only: use in-memory distributed cache.
                services.AddDistributedMemoryCache();

                identityServerBuilder.AddAuthorizationParametersMessageStore<DistributedCacheAuthorizationParametersMessageStore>();
                break;
        }
    }

    private static void ConfigureDataProtection(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        var builder = services.AddDataProtection().SetApplicationName("Duende.IdentityServer");

        var dataProtectionConfigSection = configuration.GetSection("DataProtection");
        services.Configure<DataProtectionConfig>(dataProtectionConfigSection);

        var dataProtectionSetup = new DataProtectionConfig();
        dataProtectionConfigSection.Bind(dataProtectionSetup);

        switch (dataProtectionSetup.StorageType.ToLowerInvariant())
        {
            case "azureblobstorage":
                // when Azure Blob storage is configured: store the data on Blob Storage for sharing across all instances (if necessary)
                builder.PersistKeysToAzureBlobStorage(dataProtectionSetup.ConnectionString, dataProtectionSetup.ContainerName, dataProtectionSetup.BlobName);
                break;
            case "sqlserver":
                // use SQL server to store the data protection keys
                services.AddDbContext<DataProtectionDbContext>(b => b.UseSqlServer(dataProtectionSetup.ConnectionString, x => x.EnableRetryOnFailure()));
                builder.PersistKeysToDbContext<DataProtectionDbContext>();
                break;
            default:
                // Use local file system (single instance only!)
                builder.PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(environment.ContentRootPath, "keys")));
                break;
        }

        if (!string.IsNullOrEmpty(dataProtectionSetup.KeyVaultUri))
        {
            if (!string.IsNullOrEmpty(dataProtectionSetup.KeyVaultKeyIdentifier))
            {
                builder.ProtectKeysWithAzureKeyVault(
                    new Uri(new Uri(dataProtectionSetup.KeyVaultUri),
                        new Uri(dataProtectionSetup.KeyVaultKeyIdentifier)),
                    new DefaultAzureCredential());
            }
            else if (!string.IsNullOrEmpty(dataProtectionSetup.KeyVaultCertificateName))
            {
                builder.ProtectKeysWithCertificateFromAzureKeyVault(dataProtectionSetup);
            }
        }
        else
        {
            if (OperatingSystem.IsWindows())
            {
                builder.ProtectKeysWithDpapi();
            }
            else
            {
                builder.UseEphemeralDataProtectionProvider();
            }
        }
    }

    private static IDataProtectionBuilder ProtectKeysWithCertificateFromAzureKeyVault(this IDataProtectionBuilder builder, DataProtectionConfig dataProtectionConfig)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionConfig);
        ArgumentNullException.ThrowIfNull(dataProtectionConfig.KeyVaultUri);
        ArgumentNullException.ThrowIfNull(dataProtectionConfig.KeyVaultCertificateName);

        builder.Services.AddAzureClients(clients =>
        {
            clients.AddCertificateClient(new Uri(dataProtectionConfig.KeyVaultUri));
        });

        builder.Services.AddSingleton<IActivator, AzureKeyVaultDecryptorTypeForwardingActivator>();
        builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(services =>
        {
            var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
            var certificateClient = services.GetRequiredService<CertificateClient>();
            return new ConfigureOptions<KeyManagementOptions>(options =>
            {
                options.XmlEncryptor = new AzureKeyVaultXmlEncryptor(dataProtectionConfig.KeyVaultCertificateName, certificateClient, loggerFactory);
            });
        });

        builder.Services.AddHostedService<AzureKeyVaultCertificateRefresher>();

        return builder;
    }

    private static IServiceCollection AddContentSecurityPolicy(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ContentSecurityPolicyOptions>(configuration.GetSection("CspSources"));
        services.AddSingleton(sp => sp.GetRequiredService<IOptions<ContentSecurityPolicyOptions>>().Value);

        return services;
    }

    private static IServiceCollection AddRecaptcha(this IServiceCollection services, Action<RecaptchaOptions> setupAction)
    {
        services.Configure(setupAction);
        services.AddSingleton(sp =>
        {
            var options = sp.GetRequiredService<IOptionsMonitor<RecaptchaOptions>>().CurrentValue;
            var builder = new RecaptchaEnterpriseServiceClientBuilder
            {
                JsonCredentials = options.Credentials
            };

            return builder.Build();
        });
        services.AddTransient<GoogleRecaptchaService>();

        return services;
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseStaticFiles();
        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();
        
        app.UseSession();

        app.MapDefaultControllerRoute()
            .RequireAuthorization();

        app.MapHealthChecks("/_health", new HealthCheckOptions
        {
            AllowCachingResponses = false,
            ResultStatusCodes =
            {
                [HealthStatus.Healthy] = StatusCodes.Status200OK,
                [HealthStatus.Degraded] = StatusCodes.Status200OK, // This state should indicate that everything works but some services are readonly or slower than expected.
                [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable,
            }
        });

        return app;
    }
}