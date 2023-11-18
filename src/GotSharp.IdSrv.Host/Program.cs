using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.Models;
using GotSharp.IdSrv.Host;
using IdentityExpress.Identity;
using IdentityModel;
using Microsoft.EntityFrameworkCore;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
        .Enrich.FromLogContext()
        .ReadFrom.Configuration(ctx.Configuration));

    var app = builder
        .ConfigureServices()
        .ConfigurePipeline();

    await InitializeDependenciesAsync(app);

    app.Run();
}
catch (Exception ex) when (
                            // https://github.com/dotnet/runtime/issues/60600
                            ex.GetType().Name is not "StopTheHostException"
                            // HostAbortedException was added in .NET 7, but since we target .NET 6 we
                            // need to do it this way until we target .NET 8
                            && ex.GetType().Name is not "HostAbortedException"
                        )
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}

static async Task InitializeDependenciesAsync(WebApplication app)
{
    var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
    var logger = loggerFactory.CreateLogger<Program>();
    logger.LogInformation("Initializing dependencies...");

    await InitializeDatabaseAsync(app.Services, logger);
}

static async Task InitializeDatabaseAsync(IServiceProvider serviceProvider, ILogger<Program> logger)
{
    try
    {
        using var serviceProviderScope = serviceProvider.CreateScope();

        var configDbContext = serviceProviderScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        var identityDbContext = serviceProviderScope.ServiceProvider.GetRequiredService<IdentityExpressDbContext>();
        var saveChanges = false;

        if ((await configDbContext.IdentityResources.AnyAsync()) == false)
        {
            await identityDbContext.ClaimTypes.AddRangeAsync(
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Subject,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.PreferredUserName,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Name,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.GivenName,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.MiddleName,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.FamilyName,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.NickName,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Gender,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.BirthDate,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Profile,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.PhoneNumber,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.PhoneNumberVerified,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Email,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.EmailVerified,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.WebSite,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Picture,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.ZoneInfo,
                    Reserved = true
                },
                new IdentityExpressClaimType
                {
                    Name = JwtClaimTypes.Locale,
                    Reserved = true
                }
            );

            // Add standard database content if missing (identity resources + claims)
            configDbContext.IdentityResources.AddRange(
                new IdentityResources.OpenId().ToEntity(),
                new IdentityResources.Profile().ToEntity(),
                new IdentityResources.Email().ToEntity(),
                new IdentityResources.Address().ToEntity(),
                new IdentityResources.Phone().ToEntity()
            );

            logger.LogInformation("Standard Identity Resources have been added.");
            saveChanges = true;
        }

        saveChanges |= await AddMissingClaimTypesAndScopesAsync(configDbContext, identityDbContext, logger);

        if (saveChanges)
        {
            await configDbContext.SaveChangesAsync();
            logger.LogInformation("The IDP database has been updated.");
        }
    }
    catch (Exception e)
    {
        logger.LogCritical(e, "Failed to initialize the IDP database!");
    }
}

static async Task<bool> AddMissingClaimTypesAndScopesAsync(ConfigurationDbContext configurationDbContext, IdentityExpressDbContext identityDbContext, ILogger<Program> logger)
{
    var hasChanges = false;

    var hasRoleScope = await configurationDbContext.IdentityResources.AnyAsync(x => x.Name == Scopes.Role);
    if (!hasRoleScope)
    {
        // scope is missing, but is the claim present in the user DB?
        var claimType = await identityDbContext.ClaimTypes.FirstOrDefaultAsync(x => x.Name == JwtClaimTypes.Role);
        if (claimType is null)
        {
            claimType = new IdentityExpressClaimType
            {
                Name = JwtClaimTypes.Role,
                NormalizedName = JwtClaimTypes.Role.ToUpperInvariant(),
                Description = "",
                Required = false,
                Reserved = true,
                UserEditable = false,
                ValueType = IdentityExpressClaimValueType.String
            };

            await identityDbContext.ClaimTypes.AddAsync(claimType);
            await identityDbContext.SaveChangesAsync();
        }

        await configurationDbContext.IdentityResources.AddAsync(new IdentityResource
        {
            Name = Scopes.Role,
            DisplayName = "User roles",
            Description = "Your roles",
            Emphasize = false,
            ShowInDiscoveryDocument = true,
            UserClaims = new List<string> { JwtClaimTypes.Role }
        }.ToEntity());

        hasChanges = true;
    }

    var hasImpersonatorScope = await configurationDbContext.IdentityResources.AnyAsync(x => x.Name == Scopes.Impersonation);
    if (!hasImpersonatorScope)
    {
        // scope is missing, but are the claims present in the user DB?
        var subClaimType = await identityDbContext.ClaimTypes.FirstOrDefaultAsync(x => x.Name == ClaimTypes.Impersonator);
        var nameClaimType = await identityDbContext.ClaimTypes.FirstOrDefaultAsync(x => x.Name == ClaimTypes.ImpersonatorName);

        if (subClaimType is null)
        {
            var claimType = new IdentityExpressClaimType
            {
                Name = ClaimTypes.Impersonator,
                NormalizedName = ClaimTypes.Impersonator.ToUpperInvariant(),
                Description = "Impersonator User ID",
                Required = false,
                Reserved = true,
                UserEditable = false,
                ValueType = IdentityExpressClaimValueType.String
            };

            await identityDbContext.ClaimTypes.AddAsync(claimType);
        }

        if (nameClaimType is null)
        {
            var claimType = new IdentityExpressClaimType
            {
                Name = ClaimTypes.ImpersonatorName,
                NormalizedName = ClaimTypes.ImpersonatorName.ToUpperInvariant(),
                Description = "Impersonator User",
                Required = false,
                Reserved = true,
                UserEditable = false,
                ValueType = IdentityExpressClaimValueType.String
            };

            await identityDbContext.ClaimTypes.AddAsync(claimType);
        }

        if (subClaimType is null || nameClaimType is null)
        {
            // If one or both claim types were not existing, they do now and we need to save the changes
            await identityDbContext.SaveChangesAsync();
        }

        await configurationDbContext.IdentityResources.AddAsync(new IdentityResource
        {
            Name = Scopes.Impersonation,
            DisplayName = "User impersonation",
            Description = "The user ID and name of the impersonator",
            Emphasize = false,
            ShowInDiscoveryDocument = true,
            UserClaims = new List<string> { ClaimTypes.Impersonator, ClaimTypes.ImpersonatorName }
        }.ToEntity());

        hasChanges = true;
    }

    return hasChanges;
}